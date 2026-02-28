import gostcrypto
import secrets

class Member:
    """
    Member of Cryptosystem
    """

    def __init__(self, name, ca=None):
        """
        :param name: participant name (str)
        :param ca: Certificate Authority object (for queries)
        """

        self.name = name
        self.ca = ca

        self.certificate = None
        self.other_certs = {} 

        self.curve = gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019[
            'id-tc26-gost-3410-2012-256-paramSetB'
        ]
        
        self.sign_obj = gostcrypto.gostsignature.new(
            gostcrypto.gostsignature.MODE_256,
            self.curve
        )

        self.private_key = bytearray(secrets.token_bytes(32))
        self.public_key = self.sign_obj.public_key_generate(self.private_key)
    
    def request_certificate(self):
        """
        Request certificate from CA

        :return: certificate dict or None if CA not available
        """
        if self.ca is None:
            print(f"f{self.name} CA is not initialized")
            return None

        self.certificate = self.ca.create_certificate(
            member_name=self.name,
            member_public_key=self.public_key,
            algorithm="ECDH",
            days_valid=365
        )

        print(f"{self.name}: Certificated acquired successfully (No. {self.certificate['serial_number']})")

        return self.certificate

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
        Sign data with member's private key

        :param data_bytes: data to sign (bytes)
        :return: signature (bytearray)
        """
        hash_obj = gostcrypto.gosthash.new('streebog256', data=data_bytes)
        digest = bytearray(hash_obj.digest())

        signature = self.sign_obj.sign(self.private_key, digest)
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

        # Проверка сертификата (включая проверку на аннулирование)
        is_cert_valid, cert_msg = self.ca.verify_certificate(cert)

        if not is_cert_valid:
            print(f"{self.name}: Certificate for {member_name} is INVALID: {cert_msg}")
            return False

        public_key = bytearray.fromhex(cert['subject_public_key'])

        hash_obj = gostcrypto.gosthash.new('streebog256', data=data_bytes)
        digest = bytearray(hash_obj.digest())

        is_valid = self.sign_obj.verify(public_key, digest, signature)
        if is_valid:
            print(f"{self.name}: {member_name}: Signature is valid")
        else:
            print(f"{self.name}: {member_name}: Signature is invalid")

        return is_valid
    
