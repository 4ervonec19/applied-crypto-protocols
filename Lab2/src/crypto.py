import gostcrypto
import hmac

def gost_hash(data: bytes) -> bytes:
    hash_obj = gostcrypto.gosthash.new('streebog256', data=data)
    hash_result = hash_obj.digest()
    return hash_result

def hmac_gost(key: bytes, data: bytes) -> bytes:
    hmac_obj = gostcrypto.gosthmac.new(
        'HMAC_GOSTR3411_2012_256',
        key,
        data=data
    )
    return hmac_obj.digest()

def pbkdf2_gost(password: bytes, salt: bytes, iterations: int, dklen: int = 32) -> bytes:
    pbkdf_obj = gostcrypto.gostpbkdf.new(password=password, salt=salt, counter=iterations)
    pbkdf_result = pbkdf_obj.derive(dklen)
    return pbkdf_result

def gost_mgm_encrypt(key: bytes, plaintext: bytes, nonce: bytes, aad: bytes) -> tuple[bytes, bytes]:
    cipher_obj = gostcrypto.gostcipher.new(
        'magma',
        key,
        gostcrypto.gostcipher.MODE_CTR,
        init_vect=nonce
    )
    cipher_text = cipher_obj.encrypt(plaintext)

    mac_obj = gostcrypto.gostcipher.new(
        'magma',
        key,
        gostcrypto.gostcipher.MODE_MAC
    )
    mac_obj.update(cipher_text)
    mac_obj.update(aad)
    tag = mac_obj.digest(4)
    return cipher_text, tag


def gost_mgm_decrypt(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes, aad: bytes) -> bytes:
    mac_obj = gostcrypto.gostcipher.new(
        'magma',
        key,
        gostcrypto.gostcipher.MODE_MAC
    )
    mac_obj.update(ciphertext)
    mac_obj.update(aad)
    expected_tag = mac_obj.digest(4)

    # DEBUG
    # print(f"DEBUG: expected_tag={expected_tag.hex()}, stored_tag={tag.hex()}")

    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("Authentication tag verification failed")

    cipher_obj = gostcrypto.gostcipher.new(
            'magma',
            key,
            gostcrypto.gostcipher.MODE_CTR,
            init_vect=nonce
    )
    plaintext = cipher_obj.decrypt(ciphertext)
    return plaintext

def test_gost_hash():
    data = b"test"
    h = gost_hash(data=data)
    assert len(h) == 32
    print(f"gost_hash: {h.hex()}")

def test_hmac_gost():
    import os
    key = os.urandom(32)
    data = b"test"
    mac = hmac_gost(data=data, key=key)
    assert len(mac) == 32
    print(f"hmac_gost: {mac.hex()}")

def test_pbkdf2_gost():
    import os
    import time

    password = b"master_password"
    salt = os.urandom(16)
    start = time.time()
    key = pbkdf2_gost(password, salt, iterations=1000, dklen=32)
    assert len(key) == 32
    print(f"pbkdf2_gost: {key.hex()}")
    print(f"Elapsed time: {time.time() - start:.2f}")

def test_encrypt_decrypt():
    import os

    key = os.urandom(32)
    nonce = os.urandom(4)
    aad = b"domain_hash"
    plaintext = b"my_secret_password"

    ciphertext, tag = gost_mgm_encrypt(key, plaintext, nonce, aad)
    print(f"ciphertext: {ciphertext.hex()}, tag: {tag.hex()}")
    
    decrypted = gost_mgm_decrypt(key, ciphertext, nonce, tag, aad)
    assert decrypted == plaintext
    print(f"decrypted: {decrypted}")

def test_wrong_tag():
    import os

    key = os.urandom(32)
    nonce = os.urandom(4)
    aad = b"domain_hash"
    plaintext = b"my_secret_password"
 
    ciphertext, tag = gost_mgm_encrypt(key, plaintext, nonce, aad)

    wrong_tag = os.urandom(16)
    try:
        gost_mgm_decrypt(key, ciphertext, nonce, wrong_tag, aad)
        print("ERROR: Should have raised ValueError")
    except ValueError as e:
        print(f"Correct: {e}")





if __name__ == "__main__":
    test_gost_hash()
    test_hmac_gost()
    test_pbkdf2_gost()
    test_encrypt_decrypt()
    test_wrong_tag()
