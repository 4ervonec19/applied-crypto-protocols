import gostcrypto
import secrets
import json
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

class Member:
    """
    Member of Cryptosystem
    Each member has signature keys (GOST or RSA) + ECDH keys for key exchange
    """
    SCHEME_GOST = "GOST"
    SCHEME_RSA = "RSA"

    def __init__(self, name, ca=None, scheme=SCHEME_GOST):
        """
        :param name: participant name (str)
        :param ca: Certificate Authority object (for queries)
        :param scheme: crypto scheme (GOST or RSA)
        """

        self.name = name
        self.ca = ca
        self.scheme = scheme

        self.certificate = None
        self.other_certs = {}

        # Keys for signature (GOST or RSA)
        self.gost_private_key = None
        self.gost_public_key = None
        self.rsa_key = None

        # Keys for key exchange (ECDH) - always generated for all schemes
        self.ecdh_private_key = None
        self.ecdh_public_key = None

        # Initialize signature keys based on scheme
        if scheme == "GOST":
            self.curve = gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019[
                'id-tc26-gost-3410-2012-256-paramSetB'
            ]
            self.sign_obj = gostcrypto.gostsignature.new(
                gostcrypto.gostsignature.MODE_256,
                self.curve
            )
            self.gost_private_key = bytearray(secrets.token_bytes(32))
            self.gost_public_key = self.sign_obj.public_key_generate(self.gost_private_key)
            self.public_key = self.gost_public_key

        elif scheme == "RSA":
            self.rsa_key = RSA.generate(2048)
            self.public_key = bytearray(self.rsa_key.publickey().export_key(format='DER'))

        # ECDH keys for key exchange - always generated (using pycryptodome with Curve25519)
        from Crypto.PublicKey import ECC
        self.ecdh_private_key = ECC.generate(curve='Curve25519')
        self.ecdh_public_key = self.ecdh_private_key.public_key()

    def get_exchange_public_key(self):
        """
        Get the public key for key exchange (ECDH).

        :return: exchange public key (EccKey object), or None if not available
        """
        return self.ecdh_public_key

    def get_exchange_public_key_bytes(self):
        """
        Get the public key for key exchange as DER-encoded bytes.

        :return: exchange public key as bytes, or None if not available
        """
        if self.ecdh_public_key is None:
            return None
        return bytearray(self.ecdh_public_key.export_key(format='DER'))

    def compute_shared_secret(self, other_public_key):
        """
        Compute shared secret using ECDH (Curve25519) via pycryptodome.

        :param other_public_key: other party's ECDH public key (EccKey object)
        :return: shared secret (bytearray, 32 bytes)
        """
        if self.ecdh_private_key is None:
            raise ValueError("ECDH keys not generated for this member (scheme must be ECDH or BOTH)")

        from Crypto.Protocol.DH import _compute_ecdh

        # Compute shared secret using pycryptodome's internal ECDH function
        shared_secret = _compute_ecdh(self.ecdh_private_key, other_public_key)

        # Return as bytearray
        return bytearray(shared_secret)

    def compute_shared_secret_with_cert_verify(self, other_member):
        """
        Compute shared secret using ECDH with certificate verification.
        Verifies the other party's certificate before key exchange.

        :param other_member: other party Member object
        :return: shared secret (bytearray, 32 bytes) or None if verification fails
        """
        # Check if other member has a certificate
        if other_member.certificate is None:
            print(f"{self.name}: {other_member.name} has no certificate")
            return None

        # Verify other member's certificate
        is_valid, msg = self.ca.verify_certificate(other_member.certificate)
        if not is_valid:
            print(f"{self.name}: {other_member.name}'s certificate is INVALID: {msg}")
            return None

        print(f"{self.name}: {other_member.name}'s certificate verified successfully")

        # Get other party's ECDH public key
        other_ecdh_pub = other_member.get_exchange_public_key()
        if other_ecdh_pub is None:
            print(f"{self.name}: {other_member.name} has no ECDH public key")
            return None

        # Compute shared secret
        shared_secret = self.compute_shared_secret(other_ecdh_pub)
        return shared_secret

    def encrypt_with_shared_secret(self, data_bytes, shared_secret):
        """
        Encrypt data using shared secret (AES-256-CBC).

        :param data_bytes: data to encrypt (bytes)
        :param shared_secret: shared secret from ECDH (bytearray, 32 bytes)
        :return: encrypted data with IV prepended (bytes)
        """
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        import os

        # Generate random IV
        iv = os.urandom(16)

        # Create AES cipher
        cipher = AES.new(bytes(shared_secret), AES.MODE_CBC, iv)

        # Encrypt data with padding
        encrypted = cipher.encrypt(pad(data_bytes, AES.block_size))

        # Return IV + encrypted data
        return iv + encrypted

    def decrypt_with_shared_secret(self, encrypted_data, shared_secret):
        """
        Decrypt data using shared secret (AES-256-CBC).

        :param encrypted_data: encrypted data with IV prepended (bytes)
        :param shared_secret: shared secret from ECDH (bytearray, 32 bytes)
        :return: decrypted data (bytes)
        """
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad

        # Extract IV and encrypted data
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        # Create AES cipher
        cipher = AES.new(bytes(shared_secret), AES.MODE_CBC, iv)

        # Decrypt and unpad
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)

        return decrypted

    def create_certificate_request(self, algorithm="ECDH"):
        """
        Create a Certificate Signing Request (CSR) with proof of private key ownership.
        The request is signed with the member's private key.

        :param algorithm: key algorithm identifier (str, default "ECDH")
        :return: CSR dict containing member info and signature
        """
        # Data to sign: member name + public key + algorithm
        request_data = {
            "member_name": self.name,
            "member_public_key": self.public_key.hex(),
            "algorithm": algorithm
        }

        # Serialize and sign
        data_to_sign = json.dumps(request_data, sort_keys=True).encode('utf-8')
        signature = self.sign_data(data_to_sign)

        csr = {
            "member_name": self.name,
            "member_public_key": self.public_key.hex(),
            "algorithm": algorithm,
            "request_signature": signature.hex()
        }

        print(f"{self.name}: Certificate request created and signed")
        return csr

    def request_certificate(self):
        """
        Request certificate from CA by sending a signed CSR.
        CA will verify the signature before issuing the certificate.
        After receiving the certificate, verifies CA's signature.

        :return: certificate dict or None if CA not available
        """
        if self.ca is None:
            print(f"{self.name}: CA is not initialized")
            return None

        # Create signed request (proof of private key ownership)
        csr = self.create_certificate_request(algorithm="ECDH")

        # Send CSR to CA for processing
        self.certificate = self.ca.process_certificate_request(csr)

        if self.certificate:
            # Verify that the certificate was signed by the expected CA
            is_valid, msg = self.ca.verify_certificate(self.certificate)
            if not is_valid:
                print(f"{self.name}: Certificate verification FAILED: {msg}")
                self.certificate = None
                return None

            print(f"{self.name}: Certificate acquired successfully (No. {self.certificate['serial_number']})")
            print(f"{self.name}: CA signature verified: {msg}")
        else:
            print(f"{self.name}: Certificate request rejected by CA")

        return self.certificate

    def create_revocation_request(self, reason="KEY COMPROMISE"):
        """
        Create a revocation request with proof of private key ownership.
        The request is signed with the member's private key.

        :param reason: reason for revocation (str, default "KEY COMPROMISE")
        :return: revocation request dict
        """
        if self.certificate is None:
            print(f"{self.name}: No certificate to revoke")
            return None

        # Data to sign: certificate serial + member name + reason
        request_data = {
            "member_name": self.name,
            "serial_number": self.certificate['serial_number'],
            "reason": reason
        }

        # Serialize and sign
        data_to_sign = json.dumps(request_data, sort_keys=True).encode('utf-8')
        signature = self.sign_data(data_to_sign)

        revocation_request = {
            "member_name": self.name,
            "serial_number": self.certificate['serial_number'],
            "reason": reason,
            "request_signature": signature.hex()
        }

        print(f"{self.name}: Revocation request created and signed")
        return revocation_request

    def request_revocation(self, reason="KEY COMPROMISE"):
        """
        Request revocation of own certificate from CA.
        CA will verify the signature before processing the revocation.

        :param reason: reason for revocation (str, default "KEY COMPROMISE")
        :return: True if revocation successful, False otherwise
        """
        if self.ca is None:
            print(f"{self.name}: CA is not initialized")
            return False

        if self.certificate is None:
            print(f"{self.name}: No certificate to revoke")
            return False

        # Create signed revocation request (proof of private key ownership)
        revocation_request = self.create_revocation_request(reason=reason)

        if revocation_request is None:
            return False

        # Send request to CA for processing
        result = self.ca.process_revocation_request(revocation_request)

        if result:
            print(f"{self.name}: Certificate No. {self.certificate['serial_number']} revoked successfully")
        else:
            print(f"{self.name}: Revocation request rejected by CA")

        return result

    def get_other_certificate(self, member_name):
        """
        Get certificate of another member

        :param member_name: name of the member (str)
        :return
        : certificate dict or None
        """

        if member_name in self.other_certs:
            print(f"{self.name}: {member_name}: found in cache")
            return self.other_certs[member_name]

        if self.ca is None:
            print(f"f{self.name} CA is not initialized")
            return None

        cert = self.ca.get_certificate_by_name(member_name)

        if cert is None:
            print(f"{self.name}: {member_name}: certificate not found in CA list")
            return None

        self.other_certs[member_name] = cert
        print(f"{self.name}: {member_name}: certificate acquired from CA")

        return cert

    def verify_other_certificate(self, member_name):
        """
        Verify certificate of another member

        :param member_name: name of the member to verify
        :return: (is_valid: bool, message: str)
        """
        cert = self.get_other_certificate(member_name=member_name)

        if cert is None:
            return False, f"Certificate not found for {member_name}"

        is_valid, message = self.ca.verify_certificate(cert)

        if is_valid:
            print(f":{self.name}: {member_name}: Certificate is valid")
        else:
            print(f":{self.name}: {member_name}: Certificate is invalid")

        return is_valid, message

    def sign_data(self, data_bytes):
        """
        Sign data with member's private key (GOST or RSA depending on scheme)

        :param data_bytes: data to sign (bytes)
        :return: signature (bytearray)
        """
        if self.scheme == "RSA":
            # RSA signature using PKCS#1 v1.5
            from Crypto.Hash import SHA256
            from Crypto.Signature import pkcs1_15

            hash_obj = SHA256.new(data_bytes)
            signature = pkcs1_15.new(self.rsa_key).sign(hash_obj)
            return bytearray(signature)
        else:
            # GOST signature (for GOST and BOTH schemes)
            hash_obj = gostcrypto.gosthash.new('streebog256', data=data_bytes)
            digest = bytearray(hash_obj.digest())
            signature = self.sign_obj.sign(self.gost_private_key, digest)
            return signature

    def verify_with_cert(self, data_bytes, signature, member_name):
        """
        Verify signature using another member's certificate

        :param data_bytes: original data (bytes)
        :param signature: signature to verify (bytearray)
        :param member_name: name of the signer
        :return: True if valid, False otherwise
        """
        cert = self.get_other_certificate(member_name)

        if cert is None:
            print(f"{self.name}: Certificate for {member_name} not found")
            return False

        # Check cerificate (Annul included)
        is_cert_valid, cert_msg = self.ca.verify_certificate(cert)

        if not is_cert_valid:
            print(f"{self.name}: Certificate for {member_name} is INVALID: {cert_msg}")
            return False

        # Determine signature algorithm from certificate (member's key algorithm, not CA's)
        key_algorithm = cert.get('subject_public_key_algorithm', 'GOST-34.10-2012-256')
        public_key_data = bytearray.fromhex(cert['subject_public_key'])

        if 'RSA' in key_algorithm.upper():
            # RSA signature verification
            from Crypto.Hash import SHA256
            from Crypto.Signature import pkcs1_15
            from Crypto.PublicKey import RSA

            # Reconstruct RSA public key from DER-encoded data
            rsa_public_key = RSA.import_key(public_key_data)
            hash_obj = SHA256.new(data_bytes)

            try:
                pkcs1_15.new(rsa_public_key).verify(hash_obj, bytes(signature))
                is_valid = True
            except (ValueError, TypeError):
                is_valid = False
        else:
            # GOST signature verification
            hash_obj = gostcrypto.gosthash.new('streebog256', data=data_bytes)
            digest = bytearray(hash_obj.digest())

            # Create temporary sign object for verification
            curve = gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019[
                'id-tc26-gost-3410-2012-256-paramSetB'
            ]
            sign_obj = gostcrypto.gostsignature.new(
                gostcrypto.gostsignature.MODE_256,
                curve
            )
            is_valid = sign_obj.verify(public_key_data, digest, signature)

        if is_valid:
            print(f"{self.name}: {member_name}: Signature is valid")
        else:
            print(f"{self.name}: {member_name}: Signature is invalid")

        return is_valid

