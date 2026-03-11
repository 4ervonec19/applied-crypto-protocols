import os
from key_derivation import KeyDerivator
from storage import PasswordStorage, INTEGRITY_HASH_PATH
from crypto import hmac_gost

SALT_PATH = "salt.bin"


class PasswordManager:

    def __init__(self):
        self._derivator = None
        self._storage = None
        self._k1 = None
        self._k2 = None
        self._is_logged_in = False

    def _load_or_create_salt(self) -> bytes:
        if os.path.exists(SALT_PATH):
            with open(SALT_PATH, 'rb') as f:
                return f.read()
        else:
            salt = os.urandom(16)
            with open(SALT_PATH, 'wb') as f:
                f.write(salt)
            return salt

    def init(self, master_password: str):
        salt = self._load_or_create_salt()
        self._derivator = KeyDerivator(salt=salt)
        self._k1, self._k2 = self._derivator.derive_keys(master_password.encode('utf-8'))
        self._storage = PasswordStorage()

        self._storage.load_from_file()

        if self._storage.get_all_data():
            self._storage.verify_integrity_hash()
        else:
            self._storage.save_integrity_hash()

        self._is_logged_in = True
        print("Login successful")

    def add_password(self, domain: str, password: str):
        if not self._is_logged_in:
            raise RuntimeError("Not logged in")

        self._storage.add(domain, password, self._k1, self._k2)
        self._storage.save_to_file()
        self._storage.save_integrity_hash()
        print(f"Password added for {domain}")

    def get_password(self, domain: str) -> str:
        if not self._is_logged_in:
            raise RuntimeError("Not logged in")

        password = self._storage.get(domain, self._k1, self._k2)
        print(f"Password for {domain}: {password}")
        return password

    def change_password(self, domain: str, new_password: str):
        if not self._is_logged_in:
            raise RuntimeError("Not logged in")

        self._storage.delete(domain, self._k1)
        self._storage.add(domain, new_password, self._k1, self._k2)
        self._storage.save_to_file()
        self._storage.save_integrity_hash()
        print(f"Password changed for {domain}")

    def delete_password(self, domain: str):
        if not self._is_logged_in:
            raise RuntimeError("Not logged in")

        self._storage.delete(domain, self._k1)
        self._storage.save_to_file()
        self._storage.save_integrity_hash()
        print(f"Password deleted for {domain}")

    def logout(self):
        if self._derivator:
            self._derivator.clear()
        if self._storage:
            self._storage.clear()
        self._k1 = None
        self._k2 = None
        self._is_logged_in = False
        print("Logged out, keys cleared")
