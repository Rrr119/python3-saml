# -*- coding: utf-8 -*-

""" X.509 certificate helpers.

The toolkit only needs a small amount of certificate metadata: the validity
window and a stable fingerprint for diagnostics.  Keeping this parser local
avoids adding a hard dependency on ``cryptography`` just to detect expired
IdP signing certificates.
"""

import base64
from datetime import datetime, timezone
from functools import lru_cache
from hashlib import sha1, sha256


class OneLogin_Saml2_X509_Error(ValueError):
    """Raised when a certificate cannot be decoded."""


def _pem_to_der(cert):
    if not cert:
        raise OneLogin_Saml2_X509_Error("Empty certificate")

    if isinstance(cert, bytes):
        cert = cert.decode("utf8", "replace")

    body = []
    in_cert = False
    for line in cert.replace("\r", "").split("\n"):
        line = line.strip()
        if line == "-----BEGIN CERTIFICATE-----":
            in_cert = True
            continue
        if line == "-----END CERTIFICATE-----":
            break
        if in_cert:
            body.append(line)

    if not body:
        # Allow callers to pass the raw base64 body used in SAML metadata.
        body = [line.strip() for line in cert.split("\n") if line.strip() and not line.startswith("-----")]

    try:
        return base64.b64decode("".join(body), validate=True)
    except Exception as exc:
        raise OneLogin_Saml2_X509_Error("Invalid certificate encoding: %s" % exc)


def _read_tlv(data, offset):
    if offset >= len(data):
        raise OneLogin_Saml2_X509_Error("Truncated DER value")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise OneLogin_Saml2_X509_Error("Truncated DER length")
    length = data[offset]
    offset += 1
    if length & 0x80:
        length_bytes = length & 0x7F
        if length_bytes == 0 or offset + length_bytes > len(data):
            raise OneLogin_Saml2_X509_Error("Invalid DER length")
        length = int.from_bytes(data[offset:offset + length_bytes], "big")
        offset += length_bytes
    end = offset + length
    if end > len(data):
        raise OneLogin_Saml2_X509_Error("Truncated DER value")
    return tag, offset, end


def _iter_children(data, start, end):
    offset = start
    while offset < end:
        tag, value_start, value_end = _read_tlv(data, offset)
        yield tag, value_start, value_end
        offset = value_end


def _decode_time(tag, value):
    text = value.decode("ascii")
    try:
        if tag == 0x17:  # UTCTime
            if text.endswith("Z"):
                text = text[:-1]
            fmt = "%y%m%d%H%M%S"
            dt = datetime.strptime(text, fmt)
            if dt.year >= 2050:
                dt = dt.replace(year=dt.year - 100)
        elif tag == 0x18:  # GeneralizedTime
            if text.endswith("Z"):
                text = text[:-1]
            if "." in text:
                text = text.split(".", 1)[0]
            if "+" in text or "-" in text:
                # Offsets are rare in certificates; normalise the common form.
                text = text[:14]
            if len(text) >= 14:
                dt = datetime.strptime(text[:14], "%Y%m%d%H%M%S")
            else:
                dt = datetime.strptime(text[:12], "%Y%m%d%H%M")
        else:
            raise OneLogin_Saml2_X509_Error("Unsupported certificate time tag")
    except ValueError as exc:
        raise OneLogin_Saml2_X509_Error("Invalid certificate time: %s" % exc)
    return int(dt.replace(tzinfo=timezone.utc).timestamp())


def _extract_validity(data):
    tag, start, end = _read_tlv(data, 0)
    if tag != 0x30:
        raise OneLogin_Saml2_X509_Error("Certificate is not a DER sequence")

    children = list(_iter_children(data, start, end))
    if not children or children[0][0] != 0x30:
        raise OneLogin_Saml2_X509_Error("Certificate has no TBS section")

    _, tbs_start, tbs_end = children[0]
    tbs_children = list(_iter_children(data, tbs_start, tbs_end))
    for child_tag, child_start, child_end in tbs_children:
        if child_tag != 0x30:
            continue
        validity_children = list(_iter_children(data, child_start, child_end))
        if len(validity_children) != 2:
            continue
        first_tag, first_start, first_end = validity_children[0]
        second_tag, second_start, second_end = validity_children[1]
        if first_tag in (0x17, 0x18) and second_tag in (0x17, 0x18):
            return (
                _decode_time(first_tag, data[first_start:first_end]),
                _decode_time(second_tag, data[second_start:second_end]),
            )

    raise OneLogin_Saml2_X509_Error("Certificate validity window not found")


def _extract_cn(data, start=None, end=None):
    # OID 2.5.4.3 (commonName), DER encoded as 06 03 55 04 03.
    marker = b"\x06\x03\x55\x04\x03"
    if start is None:
        start = 0
    if end is None:
        end = len(data)
    position = data.find(marker, start, end)
    while position != -1:
        offset = position + len(marker)
        if offset < len(data):
            tag, value_start, value_end = _read_tlv(data, offset)
            if tag in (0x0C, 0x13, 0x16):
                try:
                    return data[value_start:value_end].decode("utf8")
                except UnicodeDecodeError:
                    return data[value_start:value_end].decode("latin1")
        position = data.find(marker, position + 1, end)
    return None


def _extract_subject_cn(data):
    try:
        tag, start, end = _read_tlv(data, 0)
        children = list(_iter_children(data, start, end))
        _, tbs_start, tbs_end = children[0]
        tbs_children = list(_iter_children(data, tbs_start, tbs_end))
        for index, (child_tag, child_start, child_end) in enumerate(tbs_children):
            if child_tag != 0x30:
                continue
            validity_children = list(_iter_children(data, child_start, child_end))
            if len(validity_children) == 2 and all(item[0] in (0x17, 0x18) for item in validity_children):
                # The subject Name immediately follows the validity sequence.
                if index + 1 < len(tbs_children):
                    subject_tag, subject_start, subject_end = tbs_children[index + 1]
                    if subject_tag == 0x30:
                        return _extract_cn(data, subject_start, subject_end)
                break
    except Exception:
        pass
    return _extract_cn(data)


@lru_cache(maxsize=512)
def _certificate_info(cert):
    der = _pem_to_der(cert)
    not_before, not_after = _extract_validity(der)
    return {
        "not_before": not_before,
        "not_after": not_after,
        "subject": _extract_subject_cn(der),
        "fingerprint_sha1": sha1(der).hexdigest().lower(),
        "fingerprint_sha256": sha256(der).hexdigest().lower(),
    }


def get_certificate_info(cert):
    """Return decoded certificate metadata.

    Raises :class:`OneLogin_Saml2_X509_Error` for malformed input.  Callers
    should treat this as a diagnostic failure rather than a trust decision.
    """
    return dict(_certificate_info(cert))


def get_certificate_status(cert, now=None):
    """Return validity information for ``cert``.

    The returned ``status`` is one of ``valid``, ``expired``, ``not_yet_valid``
    or ``invalid``.  ``reason`` is a human readable explanation suitable for
    raising in signature validation failures.
    """
    if now is None:
        now = int(datetime.now(timezone.utc).timestamp())
    try:
        info = get_certificate_info(cert)
    except Exception as exc:
        return {
            "status": "invalid",
            "reason": "IdP signing certificate could not be decoded: %s" % exc,
            "not_before": None,
            "not_after": None,
            "subject": None,
            "fingerprint_sha1": None,
            "fingerprint_sha256": None,
        }

    info["status"] = "valid"
    info["reason"] = None
    if now < info["not_before"]:
        info["status"] = "not_yet_valid"
        info["reason"] = "IdP signing certificate is not valid before %s" % _format_time(info["not_before"])
    elif now >= info["not_after"]:
        info["status"] = "expired"
        info["reason"] = "IdP signing certificate expired on %s" % _format_time(info["not_after"])
    return info


def _format_time(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def format_certificate_status(info):
    """Build a compact diagnostic string from :func:`get_certificate_status`."""
    parts = []
    if info.get("fingerprint_sha256"):
        parts.append("sha256=%s" % info["fingerprint_sha256"])
    if info.get("subject"):
        parts.append("subject=%s" % info["subject"])
    if info.get("not_before") is not None:
        parts.append("notBefore=%s" % _format_time(info["not_before"]))
    if info.get("not_after") is not None:
        parts.append("notAfter=%s" % _format_time(info["not_after"]))
    if info.get("reason"):
        parts.append(info["reason"])
    return ", ".join(parts)
