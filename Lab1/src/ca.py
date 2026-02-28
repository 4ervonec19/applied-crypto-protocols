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

        certificate = {
            "serial_number": self.serial_counter,
            "signature_algorithm": "GOST-512",
            "issuer": self.name,
            "validity": {
                "not_before": current_time.isoformat(),
                "not_after": (current_time + timedelta(days=days_valid)).isoformat()
            },
            "subject": member_name,
            "subject_public_key_algorithm": algorithm,
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
    
    
    