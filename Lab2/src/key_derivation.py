import os
from crypto import pbkdf2_gost, hmac_gost

# Constants
SALT_SIZE = 16  
KEY_SIZE = 32
PBKDF2_ITERATIONS = 700
VECTOR_1 = b'\x01' * 32
VECTOR_2 = b'\x02' * 32 

class KeyDerivator:
    
    def __init__(self, salt: bytes = None):
        self.salt = salt if salt else os.urandom(SALT_SIZE)
        self._master_key = None
        self._k1 = None
        self._k2 = None
    
    def derive_keys(self, master_password: bytes) -> tuple[bytes, bytes]:
        """
        Выработать ключи из мастер-пароля.

        Returns:
            (k1, k2) — ключи для доменов и шифрования
        """
        self._master_key = pbkdf2_gost(master_password, self.salt, PBKDF2_ITERATIONS, KEY_SIZE)
        self._k1 = hmac_gost(self._master_key, VECTOR_1)
        self._k2 = hmac_gost(self._master_key, VECTOR_2)

        # Уничтожить master_key сразу после использования
        self._master_key = b'\x00' * len(self._master_key)
        self._master_key = None

        return self._k1, self._k2

    def get_k1(self) -> bytes:
        return self._k1
    
    def get_k2(self) -> bytes:
        return self._k2
    
    def get_salt(self) -> bytes:
        return self.salt
    
    def clear(self):
        if self._master_key:
            self._master_key = b'\x00' * len(self._master_key)
            self._master_key = None
        
        if self._k1:
            self._k1 = b'\x00' * len(self._k1)
            self._k1 = None

        if self._k2:
            self._k2 = b'\x00' * len(self._k2)
            self._k2 = None

def test_key_derivation():
    derivator = KeyDerivator()
    password = b"my_master_password"

    k, k1, k2 = derivator.derive_keys(password)

    assert len(k) == 32
    assert len(k1) == 32
    assert len(k2) == 32

    print(f"k:  {k.hex()}")
    print(f"k1:  {k1.hex()}")
    print(f"k2:  {k2.hex()}")

    derivator2 = KeyDerivator(salt=derivator.get_salt())
    k2_, k1_2, k2_2 = derivator2.derive_keys(password)

    assert k == k2_
    assert k1 == k1_2
    assert k2 == k2_2

    derivator.clear()
    assert derivator.get_k1() is None
    assert derivator.get_k2() is None
    print("Keys cleared")

if __name__ == "__main__":
    test_key_derivation()


