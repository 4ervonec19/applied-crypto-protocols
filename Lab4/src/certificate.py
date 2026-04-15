import json
from datetime import datetime


def verify_certificate(cert: dict, ca_public_key: bytes, ca_verify_func, crl: list = None) -> tuple:
    required_fields = [
        "serial_number", "signature_algorithm", "issuer", "validity",
        "subject", "subject_public_key", "signature"
    ]
    for field in required_fields:
        if field not in cert:
            return False, f"Missing field: {field}"

    cert_copy = cert.copy()
    signature_hex = cert_copy.pop("signature")
    try:
        signature = bytearray.fromhex(signature_hex)
    except ValueError:
        return False, "Invalid signature format"

    data_to_verify = json.dumps(cert_copy, sort_keys=True).encode('utf-8')

    current_time = datetime.now()
    try:
        not_before = datetime.fromisoformat(cert["validity"]["not_before"])
        not_after = datetime.fromisoformat(cert["validity"]["not_after"])
    except (KeyError, ValueError) as e:
        return False, f"Invalid dates: {e}"

    if current_time < not_before:
        return False, "Not yet valid"
    if current_time > not_after:
        return False, "Expired"

    if crl is not None:
        revoked = [e["serial_number"] for e in crl]
        if cert["serial_number"] in revoked:
            return False, f"Certificate No. {cert['serial_number']} is in CRL"

    if not ca_verify_func(data_to_verify, signature, ca_public_key):
        return False, "CA signature invalid"

    return True, "Certificate is valid"


def check_crl(serial_number: int, crl_document: dict) -> tuple:
    for entry in crl_document.get("revoked_certificates", []):
        if entry["serial_number"] == serial_number:
            return True, entry.get("reason", "Unknown")
    return False, None


def cert_to_summary(cert: dict) -> str:
    return (
        f"Certificate No. {cert.get('serial_number', '?')}:\n"
        f"  Issuer:    {cert.get('issuer', '?')}\n"
        f"  Subject:   {cert.get('subject', '?')}\n"
        f"  Algorithm: {cert.get('subject_public_key_algorithm', '?')}\n"
        f"  Key Usage: {cert.get('key_usage', '?')}\n"
        f"  Valid:     {cert.get('validity', {}).get('not_before', '?')} — "
        f"{cert.get('validity', {}).get('not_after', '?')}"
    )
