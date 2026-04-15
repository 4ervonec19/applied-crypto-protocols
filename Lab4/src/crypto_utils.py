import os
import hmac as hmac_std
import hashlib
import gostcrypto
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

# GOST Hash
def gost_hash(data: bytes) -> bytes:
    """GOST R 34.11-2012 Streebog 256."""
    return gostcrypto.gosthash.new('streebog256', data=data).digest()

# GOST HMAC
def hmac_gost(key: bytes, data: bytes) -> bytes:
    """HMAC with GOST hash."""
    return gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_256', key, data=data).digest()

# SHA-256 HMAC
def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac_std.new(key, data, hashlib.sha256).digest()


# HKDF (RFC 5869)
def hkdf_extract(salt: bytes, ikm: bytes, hash_func=None) -> bytes:
    if hash_func is None:
        hash_func = hmac_sha256
    if not salt:
        salt = b'\x00' * 32
    return hash_func(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int = 32, hash_func=None) -> bytes:
    if hash_func is None:
        hash_func = hmac_sha256
    n = (length + 31) // 32
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hash_func(prk, t + info + bytes([i]))
        okm += t
    return okm[:length]


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32, hash_func=None) -> bytes:
    prk = hkdf_extract(salt, ikm, hash_func)
    return hkdf_expand(prk, info, length, hash_func)


# AES-256-GCM
def aes_gcm_encrypt(key: bytes, plaintext: bytes, nonce: bytes, aad: bytes = b"") -> tuple:
    aesgcm = AESGCM(key)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, aad)
    return ct_with_tag[:-16], ct_with_tag[-16:]


def aes_gcm_decrypt(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext + tag, aad)


# DH (RFC 3526 Group 14, 2048-bit)
DH_GROUP14_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)
DH_GROUP14_G = 2


class DHKeyPair:
    def __init__(self):
        self.private_key = int.from_bytes(os.urandom(32), 'big') % (DH_GROUP14_P - 1) + 1
        self.public_key = pow(DH_GROUP14_G, self.private_key, DH_GROUP14_P)

    def compute_shared_secret(self, other_public_key: int) -> bytes:
        shared = pow(other_public_key, self.private_key, DH_GROUP14_P)
        shared_bytes = shared.to_bytes((shared.bit_length() + 7) // 8, 'big')
        return gost_hash(shared_bytes)


# ECDH (secp256r1)
class ECDHKeyPair:
    def __init__(self, private_key=None):
        if private_key:
            self._private_key = private_key
        else:
            self._private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    def get_public_key_bytes(self) -> bytes:
        pub = self._private_key.public_key()
        nums = pub.public_numbers()
        return nums.x.to_bytes(32, 'big') + nums.y.to_bytes(32, 'big')

    @staticmethod
    def from_public_bytes(pub_bytes: bytes):
        x = int.from_bytes(pub_bytes[:32], 'big')
        y = int.from_bytes(pub_bytes[32:], 'big')
        from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers
        pub_key = EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key(default_backend())
        pair = ECDHKeyPair()
        pair._private_key = None
        pair._public_key = pub_key
        return pair

    def compute_shared_secret(self, other_public_key_bytes: bytes) -> bytes:
        other = ECDHKeyPair.from_public_bytes(other_public_key_bytes)
        shared = self._private_key.exchange(ec.ECDH(), other._public_key)
        return gost_hash(shared)


# Signatures
class GOSTSigner:
    def __init__(self):
        self.curve = gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019[
            'id-tc26-gost-3410-2012-256-paramSetB'
        ]
        self.sign_obj = gostcrypto.gostsignature.new(
            gostcrypto.gostsignature.MODE_256, self.curve
        )
        self.private_key = bytearray(os.urandom(32))
        self.public_key = self.sign_obj.public_key_generate(self.private_key)

    def sign(self, data: bytes) -> bytes:
        digest = bytearray(gost_hash(data))
        return self.sign_obj.sign(self.private_key, digest)

    def verify(self, data: bytes, signature: bytes, public_key: bytes) -> bool:
        digest = bytearray(gost_hash(data))
        return self.sign_obj.verify(public_key, digest, signature)


class RSASigner:
    def __init__(self, key_size: int = 2048):
        from Crypto.PublicKey import RSA
        self._rsa_key = RSA.generate(key_size)
        self.public_key = self._rsa_key.publickey().export_key(format='DER')

    def sign(self, data: bytes) -> bytes:
        from Crypto.Hash import SHA256
        from Crypto.Signature import pkcs1_15
        return pkcs1_15.new(self._rsa_key).sign(SHA256.new(data))

    def verify(self, data: bytes, signature: bytes, public_key_der: bytes) -> bool:
        from Crypto.Hash import SHA256
        from Crypto.Signature import pkcs1_15
        from Crypto.PublicKey import RSA
        try:
            pkcs1_15.new(RSA.import_key(public_key_der)).verify(SHA256.new(data), signature)
            return True
        except (ValueError, TypeError):
            return False
