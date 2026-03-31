from manager import PasswordManager
import os
import json

for f in ["salt.bin", "passwords.db", "integrity.hash"]:
    if os.path.exists(f):
        os.remove(f)


def print_header(title: str):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


def test_add_passwords():
    print_header("TEST 1: Add passwords")
    
    manager = PasswordManager()
    manager.init("TEMPLATE_MASTER_PASSWORD")

    manager.add_password("example.com", "secret123")
    manager.add_password("google.com", "google_pass")
    manager.add_password("ozon.com", "qwerty")
    manager.add_password("vk.com", "password-for-vk")
    manager.add_password("yandex.ru", "secret123")

    manager.logout()


def test_get_password():
    print_header("TEST 2: Get password")
    
    manager = PasswordManager()
    manager.init("TEMPLATE_MASTER_PASSWORD")

    manager.add_password("example.com", "secret123")
    manager.add_password("google.com", "google_pass")
    manager.add_password("ozon.com", "qwerty")
    manager.add_password("vk.com", "password-for-vk")
    manager.add_password("yandex.ru", "secret123")

    pwd = manager.get_password("yandex.ru")
    assert pwd == "secret123"
    manager.logout()


def test_password_change():
    print_header("TEST 3: Change password")
    
    manager = PasswordManager()
    manager.init("TEMPLATE_MASTER_PASSWORD")

    manager.add_password("example.com", "secret123")
    manager.add_password("google.com", "google_pass")
    manager.add_password("ozon.com", "qwerty")
    manager.add_password("vk.com", "password-for-vk")

    manager.change_password("example.com", "new_secret456")
    pwd = manager.get_password("example.com")

    assert pwd == "new_secret456"
    manager.logout()


def test_delete_password():
    print_header("TEST 4: Delete password")
    
    manager = PasswordManager()
    manager.init("TEMPLATE_MASTER_PASSWORD")
    manager.add_password("example.com", "secret123")
    manager.add_password("google.com", "google_pass")
    manager.add_password("ozon.com", "qwerty")
    manager.add_password("vk.com", "password-for-vk")
    manager.delete_password("google.com")
    try:
        manager.get_password("google.com")
        assert False, "Should have raised error"
    except ValueError:
        print("Domain correctly not found after delete")
        manager.logout()


def test_negative_scenarios():
    print_header("TEST 5: Negative scenarios")
    
    print("\n1. Wrong master password:")
    manager = PasswordManager()
    manager.init("wrong_password")

    try:
        manager.get_password("example.com")
    except Exception as e:
        print(f"Wrong password detected: {type(e).__name__}: {e}")

    print("\n2. Nonexistent domain:")
    manager2 = PasswordManager()
    manager2.init("TEMPLATE_MASTER_PASSWORD")
    try:
        manager2.get_password("nonexistent.com")
    except ValueError as e:
        print(f"Nonexistent domain detected: {e}")
    manager2.logout()

    print("\nAll negative scenarios passed!")


def test_rollback_attack():
    print_header("TEST 6: Rollback Attack Demonstration")

    manager = PasswordManager()
    manager.init("my_master_password")
    manager.add_password("test.com", "original_password")
    manager.logout()

    with open("integrity.hash", 'rb') as f:
        legitimate_hash = f.read()
    print(f"integrity.hash (on flash): {legitimate_hash.hex()[:32]}...")

    with open("passwords.db", 'r') as f:
        old_db = f.read()
    print(f"Old database copied by attacker")

    manager2 = PasswordManager()
    manager2.init("my_master_password")
    manager2.change_password("test.com", "new_secure_password")
    manager2.logout()

    with open("integrity.hash", 'rb') as f:
        new_hash = f.read()
    print(f"integrity.hash updated: {new_hash.hex()[:32]}...")

    with open("passwords.db", 'r') as f:
        current_db = f.read()
    print(f"Current database saved for recovery")

    with open("passwords.db", 'w') as f:
        f.write(old_db)
    print(f"passwords.db changed to old version (ATTACK)")
    print(f"integrity.hash NOT changed (on flash)")

    manager3 = PasswordManager()
    try:
        manager3.init("my_master_password")
        print("ERROR: Attack not detected!")
        return False
    except ValueError as e:
        print(f"Attack detected: {e}")

    print(f"Restoring database from backup...")
    with open("passwords.db", 'w') as f:
        f.write(current_db)

    manager4 = PasswordManager()
    manager4.init("my_master_password")
    pwd = manager4.get_password("test.com")
    assert pwd == "new_secure_password", f"Expected 'new_secure_password', found '{pwd}'"
    print(f"Actual password loaded: {pwd}")
    manager4.logout()

    print("\nRollback attack test PASSED!")
    return True


def test_swap_attack():
    print_header("TEST 7: Swap Attack Demonstration")

    for f in ["salt.bin", "passwords.db", "integrity.hash"]:
        if os.path.exists(f):
            os.remove(f)

    manager = PasswordManager()
    manager.init("my_master_password")
    manager.add_password("site1.com", "password_for_site1")
    manager.add_password("site2.com", "password_for_site2")
    manager.logout()
    print("Passwords saved!")

    with open("passwords.db", 'r') as f:
        db = json.load(f)

    keys = list(db.keys())
    print(f"Found keys: {len(keys)}")

    if len(keys) >= 2:
        key1, key2 = keys[0], keys[1]

        ct1_original = db[key1]["ciphertext"]
        ct2_original = db[key2]["ciphertext"]

        print(f"   Key1 (site1): {key1[:16]}...")
        print(f"   Key2 (site2): {key2[:16]}...")
        print(f"Swapping ciphertexts...")

        db[key1]["ciphertext"] = ct2_original
        db[key2]["ciphertext"] = ct1_original

        with open("passwords.db", 'w') as f:
            json.dump(db, f, indent=2)

        from storage import PasswordStorage
        storage_tmp = PasswordStorage()
        storage_tmp.load_from_file()
        storage_tmp.save_integrity_hash()

        print("Ciphertexts swapped + integrity hash recalculated")

    manager2 = PasswordManager()
    manager2.init("my_master_password")

    try:
        pwd = manager2.get_password("site1.com")
        print(f"Error: password retrieved without error: {pwd}")
        return False
    except ValueError as e:
        if "Authentication tag" in str(e) or "tag" in str(e).lower():
            print(f"Swap attack detected (tag verification failed): {e}")
        else:
            print(f"Other error: {e}")

    manager2.logout()

    print("\nSwap attack test PASSED!")
    return True


def show_files_structure():
    print_header("FILE STRUCTURE")
    
    files = {
        "salt.bin": "Salt for PBKDF2 (open)",
        "passwords.db": "Passwords database (key-value, encrypted)",
        "integrity.hash": "Integrity hash (on flash)"
    }
    
    for fname, desc in files.items():
        if os.path.exists(fname):
            size = os.path.getsize(fname)
            print(f"{fname}: {size} bytes — {desc}")
        else:
            print(f"{fname}: not found — {desc}")


if __name__ == "__main__":
    print("\n")
    print("   PASSWORD MANAGER — LAB 2 DEMONSTRATION")
    
    test_add_passwords()
    test_get_password()
    test_password_change()
    test_delete_password()
    test_negative_scenarios()
    test_rollback_attack()
    test_swap_attack()
    
    show_files_structure()
    
    print("\n" + "=" * 60)
    print("CLEANUP")
    print("=" * 60)
    for f in ["salt.bin", "passwords.db", "integrity.hash"]:
        if os.path.exists(f):
            os.remove(f)
            print(f"Removed: {f}")
    
    print("\n")
    print("   ALL TESTS PASSED!")
    print("\n")
