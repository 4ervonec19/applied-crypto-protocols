import json
from datetime import datetime, timedelta
from crypto_utils import gost_hash, GOSTSigner


class CertificateAuthority:
    def __init__(self, name="CA-lab-4"):
        self.name = name
        self.serial_counter = 1

        self.gost_signer = GOSTSigner()
        self.ca_public_key = self.gost_signer.public_key
        self.ca_private_key = self.gost_signer.private_key
        self.sign_obj = self.gost_signer.sign_obj

        self.certificates = []
        self.crl = []

    def sign_data(self, data_bytes: bytes) -> bytes:
        digest = bytearray(gost_hash(data_bytes))
        return self.sign_obj.sign(self.ca_private_key, digest)

    def verify_signature(self, data_bytes: bytes, signature: bytes, public_key: bytes) -> bool:
        digest = bytearray(gost_hash(data_bytes))
        return self.sign_obj.verify(public_key, digest, signature)

    def verify_signature_rsa(self, data_bytes: bytes, signature: bytes, public_key_der: bytes) -> bool:
        from Crypto.Hash import SHA256
        from Crypto.Signature import pkcs1_15
        from Crypto.PublicKey import RSA
        try:
            rsa_pub = RSA.import_key(bytes(public_key_der))
            pkcs1_15.new(rsa_pub).verify(SHA256.new(data_bytes), bytes(signature))
            return True
        except (ValueError, TypeError):
            return False

    def detect_signature_scheme(self, signature: bytes) -> str:
        return 'RSA' if len(signature) > 100 else 'GOST'

    def verify_signature_auto(self, data_bytes: bytes, signature: bytes, public_key: bytes) -> bool:
        scheme = self.detect_signature_scheme(signature)
        if scheme == 'RSA':
            return self.verify_signature_rsa(data_bytes, signature, public_key)
        return self.verify_signature(data_bytes, signature, public_key)

    def create_certificate(self, subject_name: str, public_key: bytes,
                           key_algorithm: str = "GOST-34.10-2012-256",
                           key_usage: str = "sign", days_valid: int = 365) -> dict:
        current_time = datetime.now()

        certificate = {
            "serial_number": self.serial_counter,
            "signature_algorithm": "ГОСТ-512",
            "issuer": self.name,
            "validity": {
                "not_before": current_time.isoformat(),
                "not_after": (current_time + timedelta(days=days_valid)).isoformat()
            },
            "key_usage": key_usage,
            "subject": subject_name,
            "subject_public_key_algorithm": key_algorithm,
            "subject_public_key": public_key.hex(),
            "signature": ""
        }

        cert_data = {k: v for k, v in certificate.items() if k != "signature"}
        data_to_sign = json.dumps(cert_data, sort_keys=True).encode('utf-8')
        signature = self.sign_data(data_to_sign)
        certificate["signature"] = signature.hex()

        self.certificates.append(certificate)
        self.serial_counter += 1

        print(f"CA: Certificate issued for '{subject_name}' (No. {certificate['serial_number']})")
        return certificate

    def verify_certificate(self, certificate: dict) -> tuple:
        cert_copy = certificate.copy()
        signature_hex = cert_copy.pop("signature")
        signature = bytearray.fromhex(signature_hex)

        data_to_verify = json.dumps(cert_copy, sort_keys=True).encode('utf-8')

        current_time = datetime.now()
        not_before = datetime.fromisoformat(certificate["validity"]["not_before"])
        not_after = datetime.fromisoformat(certificate["validity"]["not_after"])

        if current_time < not_before:
            return False, "Certificate is not yet valid"
        if current_time > not_after:
            return False, "Certificate has expired"
        if self.is_certificate_revoked(certificate["serial_number"]):
            return False, "Certificate has been revoked (in CRL)"
        if not self.verify_signature(data_to_verify, signature, self.ca_public_key):
            return False, "CA signature is invalid"

        return True, "Certificate is valid"

    def revoke_certificate(self, serial_number: int, reason: str = "KEY COMPROMISE") -> bool:
        cert_found = None
        for cert in self.certificates:
            if cert["serial_number"] == serial_number:
                cert_found = cert
                break
        if cert_found is None:
            print(f"CA: Certificate No. {serial_number} not found")
            return False

        self.crl.append({
            "serial_number": serial_number,
            "revocation_date": datetime.now().isoformat(),
            "reason": reason
        })
        print(f"CA: Certificate No. {serial_number} revoked (reason: {reason})")
        return True

    def is_certificate_revoked(self, serial_number: int) -> bool:
        return any(e["serial_number"] == serial_number for e in self.crl)

    def get_crl(self) -> dict:
        current_time = datetime.now()
        crl_data = {
            "signature_algorithm": "ГОСТ-512",
            "issuer": self.name,
            "this_update": current_time.isoformat(),
            "next_update": (current_time + timedelta(days=7)).isoformat(),
            "revoked_certificates": self.crl
        }
        data_to_sign = json.dumps(crl_data, sort_keys=True).encode('utf-8')
        signature = self.sign_data(data_to_sign)
        crl_data["signature"] = signature.hex()
        return crl_data

    def get_certificate_by_name(self, subject_name: str) -> dict:
        for cert in self.certificates:
            if cert.get("subject") == subject_name:
                return cert
        return None

    def process_certificate_request(self, csr: dict) -> dict:
        member_name = csr.get("member_name")
        member_public_key_hex = csr.get("member_public_key")
        algorithm = csr.get("algorithm", "GOST-34.10-2012-256")
        request_signature_hex = csr.get("request_signature")
        key_usage = csr.get("key_usage", "sign")

        if not all([member_name, member_public_key_hex, request_signature_hex]):
            print(f"CA: Invalid CSR — missing required fields")
            return None

        try:
            member_public_key = bytearray.fromhex(member_public_key_hex)
            request_signature = bytearray.fromhex(request_signature_hex)
        except ValueError as e:
            print(f"CA: Invalid CSR — hex decoding failed: {e}")
            return None

        request_data = {
            "member_name": member_name,
            "member_public_key": member_public_key_hex,
            "algorithm": algorithm
        }
        data_to_verify = json.dumps(request_data, sort_keys=True).encode('utf-8')

        if not self.verify_signature_auto(data_to_verify, request_signature, member_public_key):
            print(f"CA: CSR signature verification failed for {member_name}")
            return None

        print(f"CA: CSR signature verified for {member_name}")
        return self.create_certificate(
            subject_name=member_name, public_key=member_public_key,
            key_algorithm=algorithm, key_usage=key_usage, days_valid=365
        )
