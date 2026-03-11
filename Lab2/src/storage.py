import json
import os
from crypto import gost_hash, hmac_gost, gost_mgm_encrypt, gost_mgm_decrypt
from Crypto.Util.Padding import pad, unpad

# Constants
MAX_PASSWORD_LENGTH = 64
NONCE_SIZE = 4
INTEGRITY_HASH_PATH = "integrity.hash"

class PasswordStorage:

    def __init__(self, db_path: str = "passwords.db"):
        self.db_path = db_path
        self._data = {}

    def _pad_password(self, password: bytes) -> bytes:
        padded_password = pad(password, MAX_PASSWORD_LENGTH)
        return padded_password
    
    def _unpad_password(self, padded: bytes) -> bytes:
        unpadded_password = unpad(padded, MAX_PASSWORD_LENGTH)
        return unpadded_password
    
    def _domain_to_key(self, domain: str, k1: bytes) -> str:
        key_bytes = hmac_gost(key=k1, data=domain.encode())
        return key_bytes.hex()
    
    def add(self, domain: str, password: str, k1: bytes, k2: bytes):
        key_bytes = hmac_gost(key=k1, data=domain.encode())
        key_hex = key_bytes.hex()
        nonce = os.urandom(4)
        plaintext = pad(password.encode('utf-8'), MAX_PASSWORD_LENGTH)
        ciphertext, tag = gost_mgm_encrypt(key=k2, plaintext=plaintext, nonce=nonce, aad=key_bytes)
        self._data[key_hex] = {
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "tag": tag.hex()
        }
    
    def get(self, domain: str, k1: bytes, k2: bytes) -> str:
        key_bytes = hmac_gost(key=k1, data=domain.encode())
        key_hex = key_bytes.hex()

        if key_hex not in self._data:
            raise ValueError(f"Domain {domain} not found in storage")

        entry = self._data[key_hex]
        nonce = bytes.fromhex(entry["nonce"])
        ciphertext = bytes.fromhex(entry["ciphertext"])
        tag = bytes.fromhex(entry["tag"])

        plaintext = gost_mgm_decrypt(key=k2, ciphertext=ciphertext, nonce=nonce, tag=tag, aad=key_bytes)
        password = unpad(plaintext, MAX_PASSWORD_LENGTH).decode('utf-8')
        return password
    
    def delete(self, domain: str, k1: bytes):
        key_hex = self._domain_to_key(domain, k1)
        if key_hex in self._data:
            del self._data[key_hex]
    
    def save_to_file(self):
        with open(self.db_path, 'w') as f:
            json.dump(self._data, f, indent=2)
    
    def load_from_file(self):
        if os.path.exists(self.db_path):
            with open(self.db_path, 'r') as f:
                self._data = json.load(f)
    
    def get_all_data(self) -> dict:
        return self._data
    
    def clear(self):
        self._data = {}
    
    def compute_integrity_hash(self) -> bytes:
        data_bytes = json.dumps(self._data, sort_keys=True).encode('utf-8')
        return gost_hash(data_bytes)

    def save_integrity_hash(self):
        hash_bytes = self.compute_integrity_hash()
        with open(INTEGRITY_HASH_PATH, 'wb') as f:
            f.write(hash_bytes)
    
    def verify_integrity_hash(self) -> bool:
        if not os.path.exists(INTEGRITY_HASH_PATH):
            return True
        
        with open(INTEGRITY_HASH_PATH, 'rb') as f:
            stored_hash = f.read()
        
        computed_hash = self.compute_integrity_hash()
        import hmac
        if not hmac.compare_digest(stored_hash, computed_hash):
            raise ValueError("Integrity check failed! Possible rollback attack.")

        return True

if __name__ == "__main__":
    import os
    from key_derivation import KeyDerivator

    storage = PasswordStorage("test.db")
    derivator = KeyDerivator()
    password = b"my_master_password"

    k, k1, k2 = derivator.derive_keys(password)
    storage.add("example.com", "secret123", k1, k2)
    storage.save_to_file()
    print("Added password")

    retrieved = storage.get("example.com", k1, k2)
    assert retrieved == "secret123"
    print(f"Got password: {retrieved}")

    # storage.delete("example.com", k1)
    # storage.save_to_file()
    # print("Deleted")

    # storage.clear()
    # derivator.clear()
    # os.remove("test.db")



    


    

    
