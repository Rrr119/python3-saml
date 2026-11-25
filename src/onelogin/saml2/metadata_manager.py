# -*- coding: utf-8 -*-

""" IdP metadata refresh and signing-certificate rotation.

The manager is intentionally lazy: it is attached to a settings object and
refreshes metadata when the configured interval elapses.  A failed refresh
never replaces a previously usable IdP configuration, which keeps existing
sessions and logins working while an IdP is temporarily unavailable.
"""

from copy import deepcopy
from datetime import datetime, timezone
from os.path import isabs, join
from threading import RLock

from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.errors import OneLogin_Saml2_Error
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.x509 import get_certificate_status
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML


class OneLogin_Saml2_IdPMetadataManager(object):
    """Refresh IdP metadata and retain old signing certs for a grace period."""

    DEFAULT_REFRESH_INTERVAL = 3600
    DEFAULT_ROTATION_GRACE_PERIOD = 86400
    DEFAULT_RETRY_INTERVAL = 60
    DEFAULT_TIMEOUT = 10

    parser_class = OneLogin_Saml2_IdPMetadataParser

    def __init__(self, settings, clock=None):
        self._settings = settings
        self._clock = clock
        self._lock = RLock()
        self._config = self._normalise_config()
        self._last_refresh = None
        self._last_attempt = None
        self._last_error = None
        self._last_error_code = None
        self._next_retry = None
        self._metadata_expire_time = None
        self._metadata_xml = None
        self._refresh_count = 0
        self._retired = {}
        self._rejected = {}
        self._refreshing = False
        self._pending_refresh_error = None
        self._metadata_applied = False

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------
    @staticmethod
    def _first(mapping, names, default=None):
        if not isinstance(mapping, dict):
            return default
        for name in names:
            if name in mapping and mapping[name] is not None:
                return mapping[name]
        return default

    def _normalise_config(self):
        idp = self._get_idp()
        settings_dict = self._get_settings_dict()
        top_settings = self._get_top_settings()
        security = settings_dict.get("security", {})
        if not isinstance(security, dict):
            security = {}
        if not isinstance(top_settings, dict):
            top_settings = {}
        metadata = idp.get("metadata", {})
        if isinstance(metadata, str):
            metadata = {"url": metadata}
        if not isinstance(metadata, dict):
            metadata = {}

        url = self._first(metadata, ("url", "metadataUrl", "metadataURL", "source"))
        if url is None:
            url = self._first(idp, ("metadataUrl", "metadataURL", "metadata_url"))
        if url is None:
            url = self._first(top_settings, ("idpMetadataUrl", "idpMetadataURL"))

        file_path = self._first(metadata, ("file", "path", "metadataFile", "metadata_file"))
        if file_path is None:
            file_path = self._first(idp, ("metadataFile", "metadata_file"))

        auto_refresh = self._first(metadata, ("autoRefresh", "auto_refresh", "enabled"), True)
        initial_refresh = self._first(metadata, ("initialRefresh", "initial_refresh", "refreshOnInit", "refresh_on_init"), True)
        refresh_interval = self._first(
            metadata,
            ("refreshInterval", "refresh_interval", "metadataRefreshInterval", "refreshIntervalSeconds", "interval"),
            self._first(
                idp,
                ("metadataRefreshInterval", "refreshInterval"),
                self._first(
                    security,
                    ("metadataRefreshInterval", "refreshInterval"),
                    self._first(top_settings, ("idpMetadataRefreshInterval", "metadataRefreshInterval"), self.DEFAULT_REFRESH_INTERVAL),
                ),
            ),
        )
        grace_period = self._first(
            metadata,
            (
                "rotationGracePeriod",
                "rotation_grace_period",
                "certificateRotationGracePeriod",
                "rotationTransitionPeriod",
                "rotationPeriod",
                "rotationWindow",
                "transitionPeriod",
                "gracePeriod",
                "gracePeriodSeconds",
                "rolloverPeriod",
                "certificateRolloverPeriod",
                "rotationOverlap",
                "transitionPeriodSeconds",
                "overlapPeriod",
            ),
            self._first(
                idp,
                ("certificateRotationGracePeriod", "certRotationGracePeriod", "rotationGracePeriod", "rotationTransitionPeriod"),
                self._first(
                    security,
                    ("certificateRotationGracePeriod", "certRotationGracePeriod", "rotationGracePeriod"),
                    self._first(
                        top_settings,
                        ("certificateRotationGracePeriod", "certRotationGracePeriod", "rotationGracePeriod"),
                        self.DEFAULT_ROTATION_GRACE_PERIOD,
                    ),
                ),
            ),
        )
        retry_interval = self._first(metadata, ("retryInterval", "retry_interval"), self.DEFAULT_RETRY_INTERVAL)

        try:
            refresh_interval = int(refresh_interval)
        except (TypeError, ValueError):
            refresh_interval = self.DEFAULT_REFRESH_INTERVAL
        try:
            grace_period = int(grace_period)
        except (TypeError, ValueError):
            grace_period = self.DEFAULT_ROTATION_GRACE_PERIOD
        try:
            retry_interval = int(retry_interval)
        except (TypeError, ValueError):
            retry_interval = self.DEFAULT_RETRY_INTERVAL

        return {
            "url": url,
            "file": file_path,
            "auto_refresh": bool(auto_refresh),
            "initial_refresh": bool(initial_refresh),
            "refresh_interval": refresh_interval,
            "rotation_grace_period": max(0, grace_period),
            "retry_interval": max(0, retry_interval),
            "validate_cert": bool(self._first(metadata, ("validateCert", "validate_cert"), self._first(idp, ("validateCert", "validate_cert"), True))),
            "cafile": self._first(metadata, ("cafile", "caFile")),
            "capath": self._first(metadata, ("capath", "caPath")),
            "timeout": self._first(metadata, ("timeout",), self._first(idp, ("metadataTimeout",), self.DEFAULT_TIMEOUT)),
            "headers": self._first(metadata, ("headers",), {}),
            "entity_id": self._first(metadata, ("entityId", "entity_id")),
            "expected_entity_id": self._first(metadata, ("expectedEntityId", "expected_entity_id")),
            "required_sso_binding": self._first(metadata, ("requiredSsoBinding",), OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT),
            "required_slo_binding": self._first(metadata, ("requiredSloBinding",), OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT),
            "verify_signature": bool(
                self._first(
                    metadata,
                    ("verifySignature", "verify_signature", "requireSignedMetadata", "require_signed_metadata"),
                    False,
                )
            ),
            "signature_cert": self._first(
                metadata,
                ("signatureCertificate", "signature_cert", "signingCertificate", "signing_cert", "x509cert"),
            ),
            "require_valid_metadata": bool(self._first(metadata, ("requireValidMetadata", "require_valid_metadata"), True)),
        }

    @property
    def enabled(self):
        return bool(self._config["url"] or self._config["file"])

    @property
    def auto_refresh(self):
        return self.enabled and self._config["auto_refresh"]

    @property
    def initial_refresh(self):
        return self.enabled and self._config["auto_refresh"] and self._config["initial_refresh"]

    def get_config(self):
        return dict(self._config)

    # ------------------------------------------------------------------
    # Settings access
    # ------------------------------------------------------------------
    def _get_idp(self):
        settings = self._settings
        if hasattr(settings, "get_idp_data"):
            return getattr(settings, "_idp", {})
        return settings.get("idp", {}) if isinstance(settings, dict) else {}

    def _set_idp(self, idp):
        settings = self._settings
        if hasattr(settings, "_idp"):
            settings._idp = idp
        elif isinstance(settings, dict):
            settings["idp"] = idp

    def _get_settings_dict(self):
        settings = self._settings
        if hasattr(settings, "_sp"):
            return {"sp": settings._sp, "idp": settings._idp, "security": settings._security}
        return settings if isinstance(settings, dict) else {}

    def _get_top_settings(self):
        settings = self._settings
        if hasattr(settings, "_raw_settings"):
            return settings._raw_settings
        return settings if isinstance(settings, dict) else {}

    # ------------------------------------------------------------------
    # Public status / rotation API
    # ------------------------------------------------------------------
    def is_due(self, now=None):
        if not self.auto_refresh:
            return False
        now = self._now(now)
        if self._next_retry is not None and now < self._next_retry:
            return False
        if self._last_refresh is None:
            return True
        interval = self._config["refresh_interval"]
        if interval <= 0:
            return True
        due = self._last_refresh + interval
        if self._metadata_expire_time is not None and self._metadata_expire_time > now:
            due = min(due, self._metadata_expire_time)
        return now >= due

    def refresh_if_due(self, now=None):
        if not self.is_due(now):
            return False
        return self.refresh(now=now)

    def refresh(self, force=True, now=None, raise_on_error=False):
        """Fetch, parse and atomically apply IdP metadata.

        ``force`` is accepted for symmetry with the settings API.  A failed
        refresh keeps the previous settings and records a diagnostic error.
        """
        if not self.enabled:
            return False
        if not force and not self.is_due(now):
            return False

        with self._lock:
            if self._refreshing:
                return False
            self._refreshing = True
            now = self._now(now)
            self._last_attempt = now
            self._pending_refresh_error = None
            try:
                xml = self._fetch_metadata()
                self._validate_metadata_document(xml, now)
                parsed = self._parse_metadata(xml)
                new_idp = deepcopy(parsed.get("idp", {}))
                expected = self._config.get("expected_entity_id")
                actual = new_idp.get("entityId")
                if expected and actual and expected != actual:
                    raise OneLogin_Saml2_Error(
                        "IdP metadata entityId mismatch: expected %s but received %s" % (expected, actual),
                        OneLogin_Saml2_Error.METADATA_INVALID,
                        reason="entity_id_mismatch",
                        details={"expected": expected, "actual": actual},
                    )

                merged_idp = self._apply_metadata(new_idp, parsed, now)
                self._set_idp(merged_idp)
                self._metadata_applied = True
                if self._pending_refresh_error is not None:
                    raise self._pending_refresh_error

                self._metadata_xml = xml
                self._last_refresh = now
                self._next_retry = None
                self._refresh_count += 1
                self._last_error = None
                self._last_error_code = None
                return True
            except Exception as exc:
                self._last_error = str(exc)
                self._last_error_code = getattr(exc, "code", OneLogin_Saml2_Error.METADATA_REFRESH_FAILED)
                self._next_retry = now + self._config["retry_interval"]
                if raise_on_error:
                    raise
                return False
            finally:
                self._refreshing = False

    def get_signing_certificates(self, include_retired=True, include_rejected=False):
        idp = self._get_idp()
        certs = self._extract_signing_certs(idp)
        fingerprints = {self._cert_fingerprint(cert) for cert in certs}
        if include_retired:
            for entry in self._retired.values():
                if entry["cert"] not in certs:
                    certs.append(entry["cert"])
                    fingerprints.add(entry["fingerprint"])
        if include_rejected:
            for entry in self._rejected.values():
                if entry["fingerprint"] not in fingerprints:
                    certs.append(entry["cert"])
        return certs

    def get_retired_certificates(self):
        return [self._public_cert_entry(entry) for entry in self._retired.values()]

    def get_rejected_certificates(self):
        return [self._public_cert_entry(entry) for entry in self._rejected.values()]

    def get_certificate_diagnostics(self):
        diagnostics = []
        active = self._extract_signing_certs(self._get_idp())
        active_fingerprints = {self._cert_fingerprint(cert) for cert in active}
        for cert in active:
            status = get_certificate_status(cert, self._now())
            status.update(
                {
                    "certificate": cert,
                    "source": "active",
                    "retiredAt": None,
                    "retireAt": None,
                }
            )
            diagnostics.append(status)
        for entry in self._retired.values():
            if entry["fingerprint"] in active_fingerprints:
                continue
            status = get_certificate_status(entry["cert"], self._now())
            status.update(
                {
                    "certificate": entry["cert"],
                    "source": "rotation",
                    "retiredAt": entry.get("retired_at"),
                    "retireAt": entry.get("retire_at"),
                }
            )
            diagnostics.append(status)
        for entry in self._rejected.values():
            status = get_certificate_status(entry["cert"], self._now())
            status.update(
                {
                    "certificate": entry["cert"],
                    "source": "rejected",
                    "rejectedAt": entry.get("rejected_at"),
                    "reason": entry.get("reason") or status.get("reason"),
                }
            )
            diagnostics.append(status)
        return diagnostics

    def get_status(self):
        now = self._now()
        next_refresh = None
        if self._last_refresh is not None:
            next_refresh = self._last_refresh + self._config["refresh_interval"]
            if self._metadata_expire_time is not None and self._metadata_expire_time > now:
                next_refresh = min(next_refresh, self._metadata_expire_time)
        elif self._next_retry is not None:
            next_refresh = self._next_retry
        return {
            "enabled": self.enabled,
            "autoRefresh": self.auto_refresh,
            "initialRefresh": self.initial_refresh,
            "url": self._config["url"],
            "file": self._config["file"],
            "lastRefresh": self._last_refresh,
            "lastAttempt": self._last_attempt,
            "nextRefresh": next_refresh,
            "lastError": self._last_error,
            "lastErrorCode": self._last_error_code,
            "refreshCount": self._refresh_count,
            "metadataValidUntil": self._metadata_expire_time,
            "refreshInterval": self._config["refresh_interval"],
            "rotationGracePeriod": self._config["rotation_grace_period"],
            "retiredCertificates": self.get_retired_certificates(),
            "rejectedCertificates": self.get_rejected_certificates(),
            "signingCertificates": self.get_certificate_diagnostics(),
            "now": now,
        }

    def get_last_error(self):
        return self._last_error

    def get_last_error_code(self):
        return self._last_error_code

    def get_metadata_xml(self):
        return self._metadata_xml

    # Alias methods keep the manager approachable from application code that
    # already uses "reload"/"update" terminology.
    def update(self, force=True, now=None, raise_on_error=False):
        return self.refresh(force=force, now=now, raise_on_error=raise_on_error)

    def reload(self, force=True, now=None, raise_on_error=False):
        return self.refresh(force=force, now=now, raise_on_error=raise_on_error)

    def refresh_now(self, now=None, raise_on_error=False):
        return self.refresh(force=True, now=now, raise_on_error=raise_on_error)

    def get_metadata_status(self):
        return self.get_status()

    def get_idp_certificates(self, include_retired=True):
        return self.get_signing_certificates(include_retired=include_retired)

    @classmethod
    def refresh_all(cls, settings_list, force=False, now=None):
        """Refresh several IdP settings objects (one per IdP)."""
        results = {}
        for settings in settings_list:
            manager = getattr(settings, "_metadata_manager", None)
            if manager is not None:
                key = manager._get_idp().get("entityId") or str(id(settings))
                results[key] = manager.refresh(force=force, now=now)
            elif isinstance(settings, dict):
                manager = cls(settings)
                key = settings.get("idp", {}).get("entityId") or str(id(settings))
                results[key] = manager.refresh(force=force, now=now)
        return results

    # ------------------------------------------------------------------
    # Fetch / parse / apply
    # ------------------------------------------------------------------
    def _now(self, now=None):
        if now is None:
            if self._clock is not None:
                return int(self._clock())
            return int(OneLogin_Saml2_Utils.now())
        return int(now)

    def _fetch_metadata(self):
        if self._config["file"]:
            path = self._config["file"]
            if not isabs(path) and hasattr(self._settings, "get_base_path"):
                path = join(self._settings.get_base_path(), path)
            try:
                with open(path, "rb") as metadata_file:
                    return metadata_file.read()
            except Exception as exc:
                raise OneLogin_Saml2_Error(
                    "Could not read IdP metadata file %s: %s" % (path, exc),
                    OneLogin_Saml2_Error.METADATA_FETCH_FAILED,
                    reason="metadata_file_unreadable",
                    details={"file": path, "error": str(exc)},
                )

        url = self._config["url"]
        if url and "://" not in url:
            path = url
            if not isabs(path) and hasattr(self._settings, "get_base_path"):
                path = join(self._settings.get_base_path(), path)
            try:
                with open(path, "rb") as metadata_file:
                    return metadata_file.read()
            except Exception as exc:
                raise OneLogin_Saml2_Error(
                    "Could not read IdP metadata file %s: %s" % (path, exc),
                    OneLogin_Saml2_Error.METADATA_FETCH_FAILED,
                    reason="metadata_file_unreadable",
                    details={"file": path, "error": str(exc)},
                )
        try:
            return self.parser_class.get_metadata(
                url,
                validate_cert=self._config["validate_cert"],
                cafile=self._config["cafile"],
                capath=self._config["capath"],
                timeout=self._config["timeout"],
                headers=self._config["headers"],
            )
        except Exception as exc:
            raise OneLogin_Saml2_Error(
                "Could not fetch IdP metadata from %s: %s" % (url, exc),
                OneLogin_Saml2_Error.METADATA_FETCH_FAILED,
                reason="metadata_fetch_failed",
                details={"url": url, "error": str(exc)},
            )

    def _validate_metadata_document(self, xml, now):
        try:
            dom = OneLogin_Saml2_XML.to_etree(xml)
        except Exception as exc:
            raise OneLogin_Saml2_Error(
                "IdP metadata is not valid XML: %s" % exc,
                OneLogin_Saml2_Error.METADATA_INVALID,
                reason="metadata_xml_invalid",
                details={"error": str(exc)},
            )

        if self._config["verify_signature"]:
            cert = self._config["signature_cert"]
            if not cert:
                raise OneLogin_Saml2_Error(
                    "IdP metadata signature verification is enabled but no signature certificate is configured",
                    OneLogin_Saml2_Error.METADATA_SIGNATURE_INVALID,
                    reason="metadata_signature_cert_missing",
                )
            cert_status = get_certificate_status(cert, now)
            if cert_status["status"] != "valid":
                raise OneLogin_Saml2_Error(
                    "IdP metadata signature certificate is unusable: %s" % cert_status["reason"],
                    OneLogin_Saml2_Error.METADATA_SIGNATURE_INVALID,
                    reason=cert_status["reason"],
                    details=cert_status,
                )
            try:
                valid = OneLogin_Saml2_Utils.validate_metadata_sign(
                    xml,
                    cert=OneLogin_Saml2_Utils.format_cert(cert),
                    validatecert=False,
                    raise_exceptions=True,
                )
            except Exception as exc:
                raise OneLogin_Saml2_Error(
                    "IdP metadata signature validation failed: %s" % exc,
                    OneLogin_Saml2_Error.METADATA_SIGNATURE_INVALID,
                    reason="metadata_signature_invalid",
                    details={"error": str(exc)},
                )
            if not valid:
                raise OneLogin_Saml2_Error(
                    "IdP metadata signature validation failed",
                    OneLogin_Saml2_Error.METADATA_SIGNATURE_INVALID,
                    reason="metadata_signature_invalid",
                )

        valid_until = dom.get("validUntil")
        cache_duration = dom.get("cacheDuration")
        try:
            expire_time = OneLogin_Saml2_Utils.get_expire_time(
                cache_duration,
                OneLogin_Saml2_Utils.parse_SAML_to_time(valid_until) if valid_until else None,
            )
        except Exception as exc:
            raise OneLogin_Saml2_Error(
                "IdP metadata has an invalid validUntil/cacheDuration value: %s" % exc,
                OneLogin_Saml2_Error.METADATA_INVALID,
                reason="metadata_expiry_invalid",
                details={"validUntil": valid_until, "cacheDuration": cache_duration},
            )
        self._metadata_expire_time = expire_time
        if self._config["require_valid_metadata"] and expire_time is not None and now > expire_time:
            raise OneLogin_Saml2_Error(
                "IdP metadata expired at %s" % OneLogin_Saml2_Utils.parse_time_to_SAML(expire_time),
                OneLogin_Saml2_Error.METADATA_EXPIRED,
                reason="metadata_expired",
                details={"validUntil": valid_until, "expireTime": expire_time},
            )

    def _parse_metadata(self, xml):
        try:
            parsed = self.parser_class.parse(
                xml,
                required_sso_binding=self._config["required_sso_binding"],
                required_slo_binding=self._config["required_slo_binding"],
                entity_id=self._config["entity_id"],
            )
        except Exception as exc:
            raise OneLogin_Saml2_Error(
                "Could not parse IdP metadata: %s" % exc,
                OneLogin_Saml2_Error.METADATA_INVALID,
                reason="metadata_parse_failed",
                details={"error": str(exc)},
            )
        if not parsed or "idp" not in parsed:
            raise OneLogin_Saml2_Error(
                "IdP metadata did not contain an IDPSSODescriptor",
                OneLogin_Saml2_Error.METADATA_INVALID,
                reason="metadata_no_idp_descriptor",
            )
        return parsed

    def _apply_metadata(self, parsed_idp, parsed, now):
        current_idp = deepcopy(self._get_idp())
        updated = deepcopy(current_idp)

        for key, value in parsed_idp.items():
            if key in ("x509cert", "x509certMulti"):
                continue
            if isinstance(value, dict) and isinstance(updated.get(key), dict):
                self._deep_merge(updated[key], value)
            else:
                updated[key] = deepcopy(value)

        new_signing = self._extract_signing_certs(parsed_idp)
        old_signing = self._extract_signing_certs(current_idp)

        active_signing = []
        active_fingerprints = set()
        for cert in new_signing:
            status = get_certificate_status(cert, now)
            if status["status"] == "valid":
                fingerprint = status["fingerprint_sha256"]
                if fingerprint not in active_fingerprints:
                    active_signing.append(OneLogin_Saml2_Utils.format_cert(cert))
                    active_fingerprints.add(fingerprint)
                self._rejected.pop(fingerprint, None)
            else:
                self._remember_rejected(cert, status, now)

        grace_period = self._config["rotation_grace_period"]
        new_fingerprints = {self._cert_fingerprint(cert) for cert in new_signing}
        for cert in old_signing:
            fingerprint = self._cert_fingerprint(cert)
            if fingerprint in new_fingerprints:
                self._retired.pop(fingerprint, None)
                continue

            status = get_certificate_status(cert, now)
            if status["status"] != "valid":
                self._retired.pop(fingerprint, None)
                self._remember_rejected(cert, status, now)
                continue

            if grace_period <= 0:
                self._retired.pop(fingerprint, None)
                self._remember_rejected(
                    cert,
                    {
                        "status": "rejected",
                        "reason": "IdP signing certificate was removed by metadata rotation and the rotation grace period is disabled",
                        "fingerprint_sha256": status["fingerprint_sha256"],
                    },
                    now,
                )
                continue

            entry = self._retired.get(fingerprint)
            if entry is None:
                retire_at = min(now + grace_period, status["not_after"])
                entry = {
                    "cert": OneLogin_Saml2_Utils.format_cert(cert),
                    "fingerprint": fingerprint,
                    "status": "valid",
                    "reason": None,
                    "retired_at": now,
                    "retire_at": retire_at,
                    "not_before": status.get("not_before"),
                    "not_after": status["not_after"],
                }
                self._retired[fingerprint] = entry
            if now < entry["retire_at"] and now < status["not_after"]:
                if fingerprint not in active_fingerprints:
                    active_signing.append(entry["cert"])
                    active_fingerprints.add(fingerprint)
                self._rejected.pop(fingerprint, None)
            else:
                self._retired.pop(fingerprint, None)
                self._remember_rejected(
                    cert,
                    {
                        "status": "expired" if now >= status["not_after"] else "rejected",
                        "reason": "IdP signing certificate is no longer valid: the rotation grace period ended at %s" % OneLogin_Saml2_Utils.parse_time_to_SAML(entry["retire_at"]),
                        "fingerprint_sha256": status["fingerprint_sha256"],
                        "not_after": status["not_after"],
                    },
                    now,
                )

        # Preserve retired certificates that were not present in the previous
        # active list (for example when a second refresh happens while old
        # assertions are still within the transition window).
        for fingerprint, entry in list(self._retired.items()):
            if fingerprint in new_fingerprints:
                self._retired.pop(fingerprint, None)
                continue
            status = get_certificate_status(entry["cert"], now)
            if now < entry["retire_at"] and now < status["not_after"]:
                if fingerprint not in active_fingerprints:
                    active_signing.append(entry["cert"])
                    active_fingerprints.add(fingerprint)
            else:
                self._retired.pop(fingerprint, None)
                self._remember_rejected(entry["cert"], status, now)

        # Clean up expired inactive state so diagnostics do not grow forever.
        for fingerprint, entry in list(self._retired.items()):
            if now >= entry.get("retire_at", now):
                self._retired.pop(fingerprint, None)

        if not active_signing:
            if new_signing:
                reasons = []
                statuses = []
                for cert in new_signing:
                    status = get_certificate_status(cert, now)
                    statuses.append(status.get("status"))
                    reason = status.get("reason") or "certificate is not usable"
                    reasons.append("%s (sha256=%s)" % (reason, status.get("fingerprint_sha256")))
                code = OneLogin_Saml2_Error.METADATA_SIGNING_CERT_EXPIRED if all(status == "expired" for status in statuses) else OneLogin_Saml2_Error.METADATA_SIGNING_CERT_MISSING
                self._pending_refresh_error = OneLogin_Saml2_Error(
                    "IdP metadata did not provide a usable signing certificate: %s" % "; ".join(reasons),
                    code,
                    reason="; ".join(reasons),
                    details={"signing_certificates": self.get_rejected_certificates()},
                )
            else:
                self._pending_refresh_error = OneLogin_Saml2_Error(
                    "IdP metadata did not contain a signing certificate",
                    OneLogin_Saml2_Error.METADATA_SIGNING_CERT_MISSING,
                    reason="metadata_signing_cert_missing",
                )

        self._update_certificate_settings(updated, parsed_idp, active_signing, now)
        self._apply_sp_metadata(parsed)
        return updated

    def _update_certificate_settings(self, updated, parsed_idp, active_signing, now):
        updated["x509cert"] = active_signing[0] if active_signing else ""

        existing_multi = deepcopy(updated.get("x509certMulti", {}))
        if not isinstance(existing_multi, dict):
            existing_multi = {}

        if active_signing:
            existing_multi["signing"] = list(active_signing)
        else:
            existing_multi.pop("signing", None)

        # Prefer the newly published encryption certificate.  Keep the old
        # valid one as a fallback during a rollover.
        encryption = self._extract_encryption_certs(parsed_idp)
        encryption += self._extract_encryption_certs(updated)

        valid_encryption = []
        seen_encryption = set()
        for cert in encryption:
            status = get_certificate_status(cert, now)
            if status["status"] != "valid":
                self._remember_rejected(cert, status, now)
                continue
            fingerprint = status["fingerprint_sha256"]
            if fingerprint not in seen_encryption:
                valid_encryption.append(OneLogin_Saml2_Utils.format_cert(cert))
                seen_encryption.add(fingerprint)
        if valid_encryption:
            existing_multi["encryption"] = valid_encryption
        else:
            existing_multi.pop("encryption", None)

        if existing_multi:
            updated["x509certMulti"] = existing_multi
        else:
            updated.pop("x509certMulti", None)

        # A cert fingerprint from a previous certificate must not silently
        # pin a new certificate.
        if active_signing:
            updated["certFingerprint"] = ""

    def _apply_sp_metadata(self, parsed):
        parsed_sp = parsed.get("sp", {})
        if not isinstance(parsed_sp, dict):
            return
        settings_dict = self._get_settings_dict()
        sp = settings_dict.get("sp")
        if isinstance(sp, dict) and "NameIDFormat" in parsed_sp:
            # Do not replace an explicit SP selection with an IdP default.
            if sp.get("NameIDFormat") in (None, OneLogin_Saml2_Constants.NAMEID_UNSPECIFIED):
                sp["NameIDFormat"] = parsed_sp["NameIDFormat"]

    @staticmethod
    def _deep_merge(target, source):
        for key, value in source.items():
            if isinstance(value, dict) and isinstance(target.get(key), dict):
                OneLogin_Saml2_IdPMetadataManager._deep_merge(target[key], value)
            else:
                target[key] = deepcopy(value)
        return target

    # ------------------------------------------------------------------
    # Certificate helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_signing_certs(idp):
        certs = []
        seen = set()
        if not isinstance(idp, dict):
            return certs
        cert = idp.get("x509cert")
        if cert:
            certs.append(cert)
            seen.add(OneLogin_Saml2_Utils.format_cert(cert))
        multi = idp.get("x509certMulti", {})
        if isinstance(multi, dict):
            for cert in multi.get("signing", []) or []:
                if cert:
                    formatted = OneLogin_Saml2_Utils.format_cert(cert)
                    if formatted not in seen:
                        certs.append(cert)
                        seen.add(formatted)
        return certs

    @staticmethod
    def _extract_encryption_certs(idp):
        certs = []
        if not isinstance(idp, dict):
            return certs
        multi = idp.get("x509certMulti", {})
        if isinstance(multi, dict):
            for cert in multi.get("encryption", []) or []:
                if cert:
                    certs.append(cert)
        return certs

    @staticmethod
    def _cert_fingerprint(cert):
        return get_certificate_status(cert)["fingerprint_sha256"] or OneLogin_Saml2_Utils.format_cert(cert)

    def _remember_rejected(self, cert, status, now):
        fingerprint = status.get("fingerprint_sha256") or self._cert_fingerprint(cert)
        self._rejected[fingerprint] = {
            "cert": OneLogin_Saml2_Utils.format_cert(cert),
            "fingerprint": fingerprint,
            "status": status.get("status"),
            "reason": status.get("reason"),
            "not_before": status.get("not_before"),
            "not_after": status.get("not_after"),
            "rejected_at": now,
        }

    @staticmethod
    def _public_cert_entry(entry):
        return {
            "certificate": entry.get("cert"),
            "fingerprint": entry.get("fingerprint"),
            "status": entry.get("status"),
            "reason": entry.get("reason"),
            "notBefore": entry.get("not_before"),
            "notAfter": entry.get("not_after"),
            "retiredAt": entry.get("retired_at"),
            "retireAt": entry.get("retire_at"),
            "rejectedAt": entry.get("rejected_at"),
        }


# The manager grew out of the IdP metadata parser, but callers commonly refer
# to it simply as the metadata manager.
OneLogin_Saml2_MetadataManager = OneLogin_Saml2_IdPMetadataManager
OneLogin_Saml2_MetadataRefreshManager = OneLogin_Saml2_IdPMetadataManager
OneLogin_Saml2_IdPMetadataRefresher = OneLogin_Saml2_IdPMetadataManager


def refresh_metadata(settings_list, force=False, now=None):
    """Convenience wrapper used when an application has several IdPs."""
    return OneLogin_Saml2_IdPMetadataManager.refresh_all(settings_list, force=force, now=now)


def refresh_idp_metadata(settings_list, force=False, now=None):
    return refresh_metadata(settings_list, force=force, now=now)


def metadata_status(settings):
    manager = getattr(settings, "_metadata_manager", None)
    if manager is None:
        return {"enabled": False}
    return manager.get_status()


def utc_timestamp():
    return int(datetime.now(timezone.utc).timestamp())
