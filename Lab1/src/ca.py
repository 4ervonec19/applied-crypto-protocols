#!/usr/bin/env python3

import json
import os
from datetime import datetime, timedelta
import gostcrypto

class CertificateAuthority:
    """
    Certification Authority Class - issues and annuls certificates.
    
    Certificate structure:
    - Certificate No.
    - CA Digital Sifnature Algorithm ID
    - CA Name
    - Starting timestamp for certificate
    - Ending timestamp for certificate
    - Key Algorithm ID
    - Member Name
    - Public Key value
    - CA Signature
    """
    
    def __init__(self, name="CA-lab-1"):
        """
        CA init
        
        :param name (str): CA name (default: CA-lab-1)
        """
        self.name = name
        self.serial_counter = 1
        
        # Key Pair for CA GOST 34.10-2012
        self.curve = gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019[
            'id-tc26-gost-3410-2012-256-paramSetB'
        ]
        self.sign_obj = gostcrypto.gostsignature.new(
            gostcrypto.gostsignature.MODE_256,
            self.curve
        )
        
        # Private Key Generation
        self.ca_private_key = self._generate_private_key()
        
        # Public Key Generation
        self.ca_public_key = self.sign_obj.public_key_generate(self.ca_private_key)
        
        # Certificates repo
        self.certificates = []
        
        # Canceled certificates repo
        self.crl = []
        
        # Stroage files
        self.repo_file = "ca_repository.json"
        self.crl_file = "ca_crl.json"
        self.ca_info_file = "ca_info.json"
    
    def _generate_private_key(self):
        """
        Generates Private Key from Random using GOST 34.10-2012

        :return: private key (bytearray, 32 bytes)
        """
        
        rand_k = bytearray([
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        ])

        random_obj = gostcrypto.gostrandom.new(
            32,
            rand_k=rand_k,
            size_s=gostcrypto.gostrandom.SIZE_S_256
        )

        private_key = bytearray(random_obj.random())

        random_obj.clear()

        return private_key

    def sign_data(self, data_bytes):
        """
        Sign data using GOST 34.10-2012
        
        :param data_bytes: data to sign (bytes)
        :return: signature (bytearray)
        """

        # Hashing the PlainText in Bytes
        hash_obj = gostcrypto.gosthash.new('streebog256', data=data_bytes)
        digest = bytearray(hash_obj.digest())

        # Making Signature of Hashed PlainText
        signature = self.sign_obj.sign(self.ca_private_key, digest)

        return signature

    def verify_signature(self, data_bytes, signature, public_key):
        """
        Verify signature using GOST 34.10-2012

        :param data_bytes: original data (bytes)
        :param signature: signature to verify (bytearray)
        :param public_key: public key for verification (bytearray)
        :return: True if signature is valid, False otherwise
        """

        # Hash of object
        hash_obj = gostcrypto.gosthash.new('streebog256', data=data_bytes)
        digest = bytearray(hash_obj.digest())

        # Verification
        is_valid = self.sign_obj.verify(public_key, digest, signature)

        return is_valid

    def verify_signature_rsa(self, data_bytes, signature, public_key_der):
        """
        Verify RSA signature using PKCS#1 v1.5

        :param data_bytes: original data (bytes)
        :param signature: signature to verify (bytes or bytearray)
        :param public_key_der: RSA public key in DER format (bytes)
        :return: True if signature is valid, False otherwise
        """
        from Crypto.Hash import SHA256
        from Crypto.Signature import pkcs1_15
        from Crypto.PublicKey import RSA

        try:
            # Reconstruct RSA public key from DER
            rsa_public_key = RSA.import_key(bytes(public_key_der))
            hash_obj = SHA256.new(data_bytes)
            pkcs1_15.new(rsa_public_key).verify(hash_obj, bytes(signature))
            return True
        except (ValueError, TypeError, Exception):
            return False

    def detect_signature_scheme(self, signature, public_key=None):
        """
        Detect signature scheme based on signature length.
        GOST 256-bit signature is 64 bytes, RSA-2048 is 256 bytes.

        :param signature: signature bytes
        :param public_key: public key bytes (unused, kept for compatibility)
        :return: 'RSA' or 'GOST'
        """
        # RSA-2048 signature is 256 bytes, GOST is 64 bytes
        if len(signature) > 100:
            return 'RSA'
        else:
            return 'GOST'

    def verify_signature_auto(self, data_bytes, signature, public_key):
        """
        Auto-detect signature scheme and verify.

        :param data_bytes: original data (bytes)
        :param signature: signature to verify (bytearray)
        :param public_key: public key for verification (bytearray)
        :return: True if signature is valid, False otherwise
        """
        scheme = self.detect_signature_scheme(signature, public_key)

        if scheme == 'RSA':
            return self.verify_signature_rsa(data_bytes, signature, public_key)
        else:
            return self.verify_signature(data_bytes, signature, public_key)

    def process_certificate_request(self, csr):
        """
        Process Certificate Signing Request (CSR) from a member.
        Verifies that the requester owns the private key by checking the CSR signature.

        :param csr: Certificate Signing Request dict with:
                    - member_name: participant name
                    - member_public_key: hex string of public key
                    - algorithm: key algorithm identifier
                    - request_signature: signature proving private key ownership
        :return: certificate dict if request is valid, None otherwise
        """
        member_name = csr.get("member_name")
        member_public_key_hex = csr.get("member_public_key")
        algorithm = csr.get("algorithm", "ECDH")
        request_signature_hex = csr.get("request_signature")

        # Validate CSR fields
        if not all([member_name, member_public_key_hex, request_signature_hex]):
            print(f"CA: Invalid CSR - missing required fields")
            return None

        # Convert public key and signature from hex
        try:
            member_public_key = bytearray.fromhex(member_public_key_hex)
            request_signature = bytearray.fromhex(request_signature_hex)
        except ValueError as e:
            print(f"CA: Invalid CSR - hex decoding failed: {e}")
            return None

        # Verify the CSR signature (proof of private key ownership)
        # Data that was signed: member_name + public_key + algorithm
        request_data = {
            "member_name": member_name,
            "member_public_key": member_public_key_hex,
            "algorithm": algorithm
        }
        data_to_verify = json.dumps(request_data, sort_keys=True).encode('utf-8')

        # Auto-detect signature scheme (GOST or RSA) and verify
        if not self.verify_signature_auto(data_to_verify, request_signature, member_public_key):
            print(f"CA: CSR signature verification failed for {member_name} - private key ownership NOT proven")
            return None

        print(f"CA: CSR signature verified for {member_name} - private key ownership confirmed")

        # Signature is valid - issue the certificate
        certificate = self.create_certificate(
            member_name=member_name,
            member_public_key=member_public_key,
            algorithm=algorithm,
            days_valid=365
        )

        return certificate

    def create_certificate(
            self,
            member_name,
            member_public_key,
            algorithm="ECDH",
            days_valid=365
        ):

        """
        Creates certificate according to structure in Task.

        :param member_name: system member name (str)
        :param member_public_key: system member public key (bytearray)
        :param algorithm: key algorithm (str, default "ECDH")
        :param days_valid: validity period in days (int, default 365)
        :return: certificate (dict)
        """

        current_time = datetime.now()

        # Detect key type based on public key length
        # RSA-2048 DER-encoded public key is typically > 100 bytes, GOST is 64 bytes
        if len(member_public_key) > 100:
            key_algorithm = "RSA-2048"
        else:
            key_algorithm = "GOST-34.10-2012-256"

        certificate = {
            "serial_number": self.serial_counter,
            "signature_algorithm": "GOST-512",  # CA's signature algorithm
            "issuer": self.name,
            "validity": {
                "not_before": current_time.isoformat(),
                "not_after": (current_time + timedelta(days=days_valid)).isoformat()
            },
            "subject": member_name,
            "subject_public_key_algorithm": key_algorithm,  # Member's key algorithm
            "subject_public_key": member_public_key.hex(),
            "signature": "" # Initialized as empty
        }

        # Full data
        cert_data = {k: v for k, v in certificate.items() if k != "signature"}

        # Data which is signed
        data_to_sign = json.dumps(cert_data, sort_keys=True).encode('utf-8')

        # Signed by Aauthority
        signature = self.sign_data(data_to_sign)
        certificate["signature"] = signature.hex() # Updated signature

        # Repo update
        self.certificates.append(certificate)

        # Num of certificates
        self.serial_counter += 1

        return certificate
    
    def verify_certificate(self, certificate):
        """
        Verify certificate validity

        :param certificate: certificate dict
        :return: (is_valid: bool, message: str)
        """
        cert_copy = certificate.copy()

        # Signature of CA
        signature_hex = cert_copy.pop("signature")
        signature = bytearray.fromhex(signature_hex)

        # Certificate body (without signature of CA)
        data_to_verify = json.dumps(cert_copy, sort_keys=True).encode('utf-8')

        # Time check
        current_time = datetime.now()
        not_before = datetime.fromisoformat(certificate["validity"]["not_before"])
        not_after = datetime.fromisoformat(certificate["validity"]["not_after"])

        if current_time < not_before:
            return False, "Certificate is not issued"
        
        if current_time > not_after:
            return False, "Certificate expired"
        
        # Annul check
        if self.is_certificate_revoked(certificate["serial_number"]):
            return False, "Certificate was annuled"

        # Signature verification check
        if not self.verify_signature(data_to_verify, signature, self.ca_public_key):
            return False, "CA Signatire is invalid"
        
        return True, "CA Signature is correct"
    
    def revoke_certificate(self, serial_number, reason="Annuled"):
        cert_found = None
        for cert in self.certificates:
            if cert["serial_number"] == serial_number:
                cert_found = cert
                break

        if cert_found is None:
            return False

        crl_instance = {
            "serial_number": serial_number,
            "revocation_date": datetime.now().isoformat(),
            "reason": reason
        }
        self.crl.append(crl_instance)

        return True

    def process_revocation_request(self, revocation_request):
        """
        Process revocation request from a member.
        Verifies that the requester owns the private key by checking the request signature.

        :param revocation_request: revocation request dict with:
                                   - member_name: participant name
                                   - serial_number: certificate serial number to revoke
                                   - reason: reason for revocation
                                   - request_signature: signature proving private key ownership
        :return: True if revocation successful, False otherwise
        """
        member_name = revocation_request.get("member_name")
        serial_number = revocation_request.get("serial_number")
        reason = revocation_request.get("reason", "KEY COMPROMISE")
        request_signature_hex = revocation_request.get("request_signature")

        # Validate request fields
        if not all([member_name, serial_number, request_signature_hex]):
            print(f"CA: Invalid revocation request - missing required fields")
            return False

        # Find the certificate to revoke
        cert_found = None
        for cert in self.certificates:
            if cert["serial_number"] == serial_number:
                cert_found = cert
                break

        if cert_found is None:
            print(f"CA: Certificate No. {serial_number} not found")
            return False

        # Verify certificate belongs to the requester
        if cert_found.get("subject") != member_name:
            print(f"CA: Certificate No. {serial_number} does not belong to {member_name}")
            return False

        # Convert signature from hex
        try:
            request_signature = bytearray.fromhex(request_signature_hex)
            member_public_key = bytearray.fromhex(cert_found["subject_public_key"])
        except ValueError as e:
            print(f"CA: Invalid revocation request - hex decoding failed: {e}")
            return False

        # Verify the revocation request signature (proof of private key ownership)
        request_data = {
            "member_name": member_name,
            "serial_number": serial_number,
            "reason": reason
        }
        data_to_verify = json.dumps(request_data, sort_keys=True).encode('utf-8')

        if not self.verify_signature_auto(data_to_verify, request_signature, member_public_key):
            print(f"CA: Revocation request signature verification failed for {member_name}")
            return False

        print(f"CA: Revocation request signature verified for {member_name}")

        # Signature is valid - revoke the certificate
        result = self.revoke_certificate(serial_number, reason)

        if result:
            print(f"CA: Certificate No. {serial_number} revoked for reason: {reason}")

        return result
    
    def is_certificate_revoked(self, serial_number):
        for entry in self.crl:
            if entry["serial_number"] == serial_number:
                return True
        return False
    
    def get_crl(self):
        """
        Get Certificate Revocation List (CRL)

        :return: CRL document (dict)
        """

        current_time = datetime.now()

        # CRL data structure according to task
        crl_data = {
            "signature_algorithm": "ГОСТ-512",
            "issuer": self.name,
            "this_update": current_time.isoformat(),
            "next_update": (current_time + timedelta(days=7)).isoformat(),
            "revoked_certificates": self.crl
        }

        # Data
        data_to_sign = json.dumps(crl_data, sort_keys=True).encode('utf-8')

        # Signature of CA
        signature = self.sign_data(data_to_sign)

        # Adding signature
        crl_document = crl_data.copy()
        crl_document["signature"] = signature.hex()

        return crl_document
    
    def save_to_files(self):
        # CA info
        ca_info = {
            "name": self.name,
            "public_key": self.ca_public_key.hex(),
            "serial_counter": self.serial_counter
        }
        with open(self.ca_info_file, 'w', encoding='utf-8') as f:
            json.dump(ca_info, f, indent=2, ensure_ascii=False)
        
        # repo
        with open(self.repo_file, 'w', encoding='utf-8') as f:
            json.dump(self.certificates, f, indent=2, ensure_ascii=False)
        
        # CRL
        crl_doc = self.get_crl()
        with open(self.crl_file, 'w', encoding='utf-8') as f:
            json.dump(crl_doc, f, indent=2, ensure_ascii=False)

    def load_from_files(self):
        import os

        if not os.path.exists(self.ca_info_file):
            return False
        
        with open(self.ca_info_file, 'r', encoding='utf-8') as f:
            ca_info = json.load(f)
        
        self.name = ca_info["name"]
        self.ca_public_key = bytearray.fromhex(ca_info["public_key"])
        self.serial_counter = ca_info["serial_counter"]

        with open(self.repo_file, 'r', encoding='utf-8') as f:
            self.certificates = json.load(f)
        
        if os.path.exists(self.crl_file):
            with open(self.crl_file, 'r', encoding='utf-8') as f:
                crl_doc = json.load(f)
                self.crl = crl_doc.get("revoked_certificates", [])
        
        return True
    
    def get_certificate_by_name(self, member_name):
        """
        Get certificate by member name from repository
        
        :param member_name: name to search
        :return: certificate dict or None
        """
        for cert in self.certificates:
            if cert.get("subject") == member_name:
                return cert
        
        return None
    
    
    