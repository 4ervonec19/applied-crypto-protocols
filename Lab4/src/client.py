import os
import json
import hmac as hmac_std
from crypto_utils import (
    gost_hash, hkdf, hkdf_extract, hkdf_expand,
    aes_gcm_encrypt, aes_gcm_decrypt,
    DHKeyPair, ECDHKeyPair, GOSTSigner
)
from config import (
    CIPHER_SUITE_AES_GCM_SHA256, CIPHER_SUITE_ECDHE_ECDSA,
    KEY_SIZE, NONCE_SIZE, HANDSHAKE_NONCE_SIZE,
    HKDF_INFO_HANDSHAKE, HKDF_INFO_CLIENT_TRAFFIC, HKDF_INFO_SERVER_TRAFFIC,
    HKDF_INFO_KEY_UPDATE, AUTH_MODE_MUTUAL
)


class Client:
    def __init__(self, name: str, ca, certificate: dict = None,
                 gost_signer: GOSTSigner = None,
                 group_type: str = "ECDH", auth_mode: str = "one_way"):
        self.name = name
        self.ca = ca
        self.certificate = certificate
        self.signer = gost_signer
        self.group_type = group_type
        self.auth_mode = auth_mode

        if group_type == "DH":
            self.key_pair = DHKeyPair()
        else:
            self.key_pair = ECDHKeyPair()

        self.session = None
        self._last_msg1 = None
        self._c1 = None

    def _derive_handshake_keys(self, shared_secret: bytes, transcript: bytes) -> dict:
        salt = gost_hash(transcript)
        prk = hkdf_extract(salt, shared_secret)

        handshake_key = hkdf_expand(prk, HKDF_INFO_HANDSHAKE, KEY_SIZE * 2)
        ksh = handshake_key[:KEY_SIZE]
        ksm = handshake_key[KEY_SIZE:]

        client_traffic = hkdf_expand(prk, HKDF_INFO_CLIENT_TRAFFIC, KEY_SIZE)
        server_traffic = hkdf_expand(prk, HKDF_INFO_SERVER_TRAFFIC, KEY_SIZE)

        return {"ksh": ksh, "ksm": ksm, "kc_to_s": client_traffic, "ks_to_c": server_traffic, "prk": prk}

    def _update_traffic_keys(self, old_key: bytes) -> bytes:
        return hkdf(ikm=b'\x00' + old_key, salt=b'', info=HKDF_INFO_KEY_UPDATE, length=KEY_SIZE)

    def create_message1(self) -> dict:
        print(f"\n{'='*60}")
        print(f"  {self.name}: Creating Message 1 (ClientHello)")
        print(f"{'='*60}")

        if self.group_type == "DH":
            offer = [CIPHER_SUITE_AES_GCM_SHA256]
        else:
            offer = [CIPHER_SUITE_ECDHE_ECDSA, CIPHER_SUITE_AES_GCM_SHA256]

        if self.group_type == "DH":
            u_hex = hex(self.key_pair.public_key)
        else:
            u_hex = self.key_pair.get_public_key_bytes().hex()

        nc = os.urandom(HANDSHAKE_NONCE_SIZE)

        msg1 = {
            "offer": offer, "u": u_hex, "Nc": nc.hex(),
            "auth_mode": self.auth_mode, "group_type": self.group_type
        }

        print(f"  {self.name}: Offer: {offer}")
        print(f"  {self.name}: Public key (u): {u_hex[:32]}...")
        print(f"  {self.name}: Nonce (Nc): {nc.hex()[:32]}...")
        print(f"  {self.name}: Auth mode: {self.auth_mode}")
        print(f"  {self.name}: Group type: {self.group_type}")
        return msg1

    def process_message2(self, msg2: dict) -> bool:
        print(f"\n{'='*60}")
        print(f"  {self.name}: Processing Message 2 (ServerHello)")
        print(f"{'='*60}")

        mode = msg2.get("mode")
        v_hex = msg2.get("v")
        ns_hex = msg2.get("Ns")
        ns = bytes.fromhex(ns_hex)

        print(f"  {self.name}: Mode: {mode}")
        print(f"  {self.name}: Server public key (v): {v_hex[:32]}...")
        print(f"  {self.name}: Server nonce (Ns): {ns.hex()[:32]}...")

        if self.group_type == "DH":
            v_int = int(v_hex, 16)
            shared_secret = self.key_pair.compute_shared_secret(v_int)
        else:
            v_bytes = bytes.fromhex(v_hex)
            shared_secret = self.key_pair.compute_shared_secret(v_bytes)
        print(f"  {self.name}: Computed {self.group_type} shared secret")

        enc = msg2.get("encrypted", {})
        enc_nonce = bytes.fromhex(enc["nonce"])
        ciphertext = bytes.fromhex(enc["ciphertext"])
        tag = bytes.fromhex(enc["tag"])

        nc_hex = self._last_msg1["Nc"]
        u_hex = self._last_msg1["u"]
        offer = self._last_msg1["offer"]

        transcript_data = json.dumps({
            "offer": offer, "u": u_hex, "Nc": nc_hex,
            "mode": mode, "v": v_hex, "Ns": ns_hex
        }, sort_keys=True).encode('utf-8')

        keys = self._derive_handshake_keys(shared_secret, transcript_data)
        ksh = keys["ksh"]
        ksm = keys["ksm"]

        try:
            decrypted = aes_gcm_decrypt(ksh, ciphertext, enc_nonce, tag)
            msg2_data = json.loads(decrypted)
        except Exception as e:
            print(f"  {self.name}: FAILED to decrypt Message 2: {e}")
            return False

        print(f"  {self.name}: Decrypted Message 2 encrypted part")

        c1 = msg2_data.get("c1")
        c2 = msg2_data.get("c2")
        c3_hex = msg2_data.get("c3")
        c4_hex = msg2_data.get("c4")

        print(f"  {self.name}: Verifying server certificate...")
        is_valid, msg = self.ca.verify_certificate(c2)
        if not is_valid:
            print(f"  {self.name}: Server certificate INVALID: {msg}")
            return False
        print(f"  {self.name}: Server certificate VALID: {msg}")

        c3 = bytearray.fromhex(c3_hex)
        server_pub_key = bytearray.fromhex(c2["subject_public_key"])
        if not self.ca.verify_signature(transcript_data, c3, server_pub_key):
            print(f"  {self.name}: Server signature verification FAILED")
            return False
        print(f"  {self.name}: Server signature verified")

        c4 = bytes.fromhex(c4_hex)
        expected_hmac = hmac_std.new(ksm, transcript_data, 'sha256').digest()
        if not hmac_std.compare_digest(c4, expected_hmac):
            print(f"  {self.name}: HMAC verification FAILED")
            return False
        print(f"  {self.name}: HMAC verified")

        self.session = {
            "group_type": self.group_type, "auth_mode": self.auth_mode,
            "shared_secret": shared_secret, "keys": keys,
            "transcript": transcript_data, "server_certificate": c2,
            "msg_counter": 0, "handshake_complete": False
        }
        self._c1 = c1
        print(f"  {self.name}: Message 2 processed successfully")
        return True

    def create_message3(self) -> dict:
        print(f"\n{'='*60}")
        print(f"  {self.name}: Creating Message 3 (ClientFinished)")
        print(f"{'='*60}")

        if self.auth_mode != AUTH_MODE_MUTUAL:
            print(f"  {self.name}: One-way auth — no Message 3 needed")
            return {}

        if self.certificate is None:
            print(f"  {self.name}: Mutual auth required, but no certificate available")
            return {}

        c5 = self.certificate
        transcript_with_c5 = self.session["transcript"] + json.dumps(c5, sort_keys=True).encode('utf-8')
        c6 = self.signer.sign(transcript_with_c5)
        c7 = hmac_std.new(self.session["keys"]["ksm"], transcript_with_c5, 'sha256').digest()

        payload = json.dumps({"c5": c5, "c6": c6.hex(), "c7": c7.hex()}, sort_keys=True).encode('utf-8')
        enc_nonce = os.urandom(NONCE_SIZE)
        ciphertext, tag = aes_gcm_encrypt(self.session["keys"]["ksh"], payload, enc_nonce)

        msg3 = {"encrypted": {"nonce": enc_nonce.hex(), "ciphertext": ciphertext.hex(), "tag": tag.hex()}}
        print(f"  {self.name}: Message 3 prepared (encrypted c5, c6, c7)")
        return msg3

    def send_data(self, data: bytes) -> dict:
        if not self.session or not self.session.get("handshake_complete"):
            raise ValueError(f"{self.name}: No established session")

        msg_num = self.session["msg_counter"]
        self.session["msg_counter"] += 1

        nonce = os.urandom(NONCE_SIZE)
        aad = json.dumps({"msg_num": msg_num, "direction": "c->s"}).encode()
        ciphertext, tag = aes_gcm_encrypt(self.session["keys"]["kc_to_s"], data, nonce, aad)

        print(f"  {self.name}: Sending to Server (msg #{msg_num}): '{data.decode()}'")
        print(f"  {self.name}: Encrypted (nonce={nonce.hex()[:16]}..., ct={ciphertext.hex()[:32]}...)")

        return {"msg_num": msg_num, "nonce": nonce.hex(), "ciphertext": ciphertext.hex(), "tag": tag.hex(), "aad": aad.hex()}

    def receive_data(self, encrypted_msg: dict) -> bytes:
        if not self.session or not self.session.get("handshake_complete"):
            raise ValueError(f"{self.name}: No established session")

        nonce = bytes.fromhex(encrypted_msg["nonce"])
        ciphertext = bytes.fromhex(encrypted_msg["ciphertext"])
        tag = bytes.fromhex(encrypted_msg["tag"])
        aad = bytes.fromhex(encrypted_msg["aad"])

        plaintext = aes_gcm_decrypt(self.session["keys"]["ks_to_c"], ciphertext, nonce, tag, aad)
        msg_num = encrypted_msg["msg_num"]
        print(f"  {self.name}: Received from Server (msg #{msg_num}): '{plaintext.decode()}'")
        return plaintext

    def initiate_key_update(self) -> dict:
        if not self.session or not self.session.get("handshake_complete"):
            raise ValueError(f"{self.name}: No established session")

        old_kc = self.session["keys"]["kc_to_s"]
        old_ks = self.session["keys"]["ks_to_c"]
        self.session["keys"]["kc_to_s"] = self._update_traffic_keys(old_kc)
        self.session["keys"]["ks_to_c"] = self._update_traffic_keys(old_ks)
        print(f"  {self.name}: Traffic keys updated (initiated by client)")

        return {"type": "KeyUpdate", "update_requested": True}

    def handle_key_update(self) -> bool:
        if not self.session or not self.session.get("handshake_complete"):
            return False

        old_kc = self.session["keys"]["kc_to_s"]
        old_ks = self.session["keys"]["ks_to_c"]
        self.session["keys"]["kc_to_s"] = self._update_traffic_keys(old_kc)
        self.session["keys"]["ks_to_c"] = self._update_traffic_keys(old_ks)
        print(f"  {self.name}: Keys updated (requested by server)")
        return True

    def full_handshake(self, server) -> bool:
        msg1 = self.create_message1()
        self._last_msg1 = msg1

        msg2 = server.handshake_receive_message1(msg1, self.name)

        if not self.process_message2(msg2):
            print(f"  {self.name}: Handshake FAILED at Message 2")
            return False

        msg3 = self.create_message3()

        if self.auth_mode == AUTH_MODE_MUTUAL:
            if not server.handshake_receive_message3(msg3, self.name):
                print(f"  {self.name}: Handshake FAILED at Message 3")
                return False
        else:
            session = server.sessions.get(self.name)
            if session:
                session["handshake_complete"] = True
                print(f"  Server: Handshake COMPLETED with {self.name} (one-way auth)")
                print(f"  Server: Protected channel established")

        self.session["handshake_complete"] = True
        print(f"\n  {self.name}: *** Protected channel established ***")
        return True
