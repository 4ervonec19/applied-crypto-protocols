import os
import json
import hmac as hmac_std
from crypto_utils import (
    gost_hash, hkdf, hkdf_extract, hkdf_expand,
    aes_gcm_encrypt, aes_gcm_decrypt,
    DHKeyPair, ECDHKeyPair, GOSTSigner
)
from config import (
    SUPPORTED_CIPHER_SUITES, KEY_SIZE, NONCE_SIZE, HANDSHAKE_NONCE_SIZE,
    HKDF_INFO_HANDSHAKE, HKDF_INFO_CLIENT_TRAFFIC, HKDF_INFO_SERVER_TRAFFIC,
    HKDF_INFO_KEY_UPDATE, AUTH_MODE_MUTUAL, AUTH_MODE_ONE_WAY
)


class Server:
    def __init__(self, ca, certificate, gost_signer: GOSTSigner):
        self.ca = ca
        self.certificate = certificate
        self.signer = gost_signer
        self.dh_key_pair = DHKeyPair()
        self.ecdh_key_pair = ECDHKeyPair()
        self.sessions = {}

    def _select_cipher_suite(self, offer: list, client_name: str) -> str:
        for suite in offer:
            if suite in SUPPORTED_CIPHER_SUITES:
                print(f"  Server: Selected cipher suite '{suite}' for {client_name}")
                return suite
        raise ValueError(f"No supported cipher suite in offer: {offer}")

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

    def handshake_receive_message1(self, msg1: dict, client_name: str) -> dict:
        print(f"\n{'='*60}")
        print(f"  SERVER: Processing Message 1 from {client_name}")
        print(f"{'='*60}")

        offer = msg1.get("offer", [])
        u_hex = msg1.get("u", "")
        nc = bytes.fromhex(msg1.get("Nc", ""))
        auth_mode = msg1.get("auth_mode", AUTH_MODE_ONE_WAY)
        group_type = msg1.get("group_type", "ECDH")

        print(f"  Server: Received offer: {offer}")
        print(f"  Server: Received client public key (u): {u_hex[:32]}...")
        print(f"  Server: Received nonce (Nc): {nc.hex()[:32]}...")
        print(f"  Server: Auth mode: {auth_mode}")
        print(f"  Server: Group type: {group_type}")

        mode = self._select_cipher_suite(offer, client_name)
        ns = os.urandom(HANDSHAKE_NONCE_SIZE)
        print(f"  Server: Generated nonce (Ns): {ns.hex()[:32]}...")

        if group_type == "DH":
            v_int = self.dh_key_pair.public_key
            v_hex = hex(v_int)
            print(f"  Server: Using DH, public key (v): {v_hex[:32]}...")
        else:
            v_bytes = self.ecdh_key_pair.get_public_key_bytes()
            v_hex = v_bytes.hex()
            print(f"  Server: Using ECDH, public key (v): {v_hex[:32]}...")

        if group_type == "DH":
            u_int = int(u_hex, 16)
            shared_secret = self.dh_key_pair.compute_shared_secret(u_int)
        else:
            u_bytes = bytes.fromhex(u_hex)
            shared_secret = self.ecdh_key_pair.compute_shared_secret(u_bytes)
        print(f"  Server: Computed {group_type} shared secret")

        transcript_data = json.dumps({
            "offer": offer, "u": u_hex, "Nc": nc.hex(),
            "mode": mode, "v": v_hex, "Ns": ns.hex()
        }, sort_keys=True).encode('utf-8')

        keys = self._derive_handshake_keys(shared_secret, transcript_data)
        ksh = keys["ksh"]
        ksm = keys["ksm"]
        print(f"  Server: Derived handshake keys (ksh, ksm)")

        c1 = "cert_request" if auth_mode == AUTH_MODE_MUTUAL else None
        c2 = self.certificate
        c3 = self.signer.sign(transcript_data)
        c4 = hmac_std.new(ksm, transcript_data, 'sha256').digest()

        encrypted_payload = json.dumps({"c1": c1, "c2": c2, "c3": c3.hex(), "c4": c4.hex()}, sort_keys=True).encode('utf-8')
        enc_nonce = os.urandom(NONCE_SIZE)
        ciphertext, tag = aes_gcm_encrypt(ksh, encrypted_payload, enc_nonce)

        msg2 = {
            "mode": mode, "v": v_hex, "Ns": ns.hex(),
            "encrypted": {"nonce": enc_nonce.hex(), "ciphertext": ciphertext.hex(), "tag": tag.hex()}
        }

        self.sessions[client_name] = {
            "group_type": group_type, "auth_mode": auth_mode,
            "u_hex": u_hex, "nc": nc, "ns": ns,
            "shared_secret": shared_secret, "keys": keys,
            "transcript": transcript_data, "msg_counter": 0,
            "handshake_complete": False
        }

        if auth_mode == AUTH_MODE_ONE_WAY:
            print(f"  Server: One-way auth — server certificate verified on client side")

        print(f"  Server: Message 2 prepared (open + encrypted parts)")
        return msg2

    def handshake_receive_message3(self, msg3: dict, client_name: str) -> bool:
        print(f"\n{'='*60}")
        print(f"  SERVER: Processing Message 3 from {client_name}")
        print(f"{'='*60}")

        session = self.sessions.get(client_name)
        if session is None:
            print(f"  Server: No session found for {client_name}")
            return False

        enc = msg3.get("encrypted", {})
        enc_nonce = bytes.fromhex(enc["nonce"])
        ciphertext = bytes.fromhex(enc["ciphertext"])
        tag = bytes.fromhex(enc["tag"])

        try:
            decrypted = aes_gcm_decrypt(session["keys"]["ksh"], ciphertext, enc_nonce, tag)
            msg3_data = json.loads(decrypted)
        except Exception as e:
            print(f"  Server: FAILED to decrypt Message 3: {e}")
            return False

        c5 = msg3_data.get("c5")
        c6_hex = msg3_data.get("c6")
        c7_hex = msg3_data.get("c7")
        print(f"  Server: Decrypted Message 3")

        if session["auth_mode"] == AUTH_MODE_MUTUAL:
            if c5 is None:
                print(f"  Server: Mutual auth required, but no client certificate provided")
                return False

            is_valid, msg = self.ca.verify_certificate(c5)
            if not is_valid:
                print(f"  Server: Client certificate INVALID: {msg}")
                return False
            print(f"  Server: Client certificate verified: {msg}")

            if c6_hex is None:
                print(f"  Server: No client signature in Message 3")
                return False

            c6 = bytearray.fromhex(c6_hex)
            transcript_with_c5 = session["transcript"] + json.dumps(c5, sort_keys=True).encode('utf-8')
            client_pub_key = bytearray.fromhex(c5["subject_public_key"])

            if not self.ca.verify_signature(transcript_with_c5, c6, client_pub_key):
                print(f"  Server: Client signature verification FAILED")
                return False
            print(f"  Server: Client signature verified")

            c7 = bytes.fromhex(c7_hex)
            expected_hmac = hmac_std.new(session["keys"]["ksm"], transcript_with_c5, 'sha256').digest()
            if not hmac_std.compare_digest(c7, expected_hmac):
                print(f"  Server: HMAC verification FAILED")
                return False
            print(f"  Server: HMAC verified")

        print(f"  Server: Handshake COMPLETED with {client_name}")
        print(f"  Server: Protected channel established")
        session["handshake_complete"] = True
        return True

    def send_data(self, data: bytes, client_name: str) -> dict:
        session = self.sessions.get(client_name)
        if not session or not session.get("handshake_complete"):
            raise ValueError(f"No established session with {client_name}")

        msg_num = session["msg_counter"]
        session["msg_counter"] += 1

        nonce = os.urandom(NONCE_SIZE)
        aad = json.dumps({"msg_num": msg_num, "direction": "s->c"}).encode()
        ciphertext, tag = aes_gcm_encrypt(session["keys"]["ks_to_c"], data, nonce, aad)

        print(f"  Server: Sending to {client_name} (msg #{msg_num}): '{data.decode()}'")
        print(f"  Server: Encrypted (nonce={nonce.hex()[:16]}..., ct={ciphertext.hex()[:32]}...)")

        return {"msg_num": msg_num, "nonce": nonce.hex(), "ciphertext": ciphertext.hex(), "tag": tag.hex(), "aad": aad.hex()}

    def receive_data(self, encrypted_msg: dict, client_name: str) -> bytes:
        session = self.sessions.get(client_name)
        if not session or not session.get("handshake_complete"):
            raise ValueError(f"No established session with {client_name}")

        nonce = bytes.fromhex(encrypted_msg["nonce"])
        ciphertext = bytes.fromhex(encrypted_msg["ciphertext"])
        tag = bytes.fromhex(encrypted_msg["tag"])
        aad = bytes.fromhex(encrypted_msg["aad"])

        plaintext = aes_gcm_decrypt(session["keys"]["kc_to_s"], ciphertext, nonce, tag, aad)
        msg_num = encrypted_msg["msg_num"]
        print(f"  Server: Received from {client_name} (msg #{msg_num}): '{plaintext.decode()}'")
        return plaintext

    def handle_key_update(self, client_name: str, update_requested: bool = False) -> dict:
        session = self.sessions.get(client_name)
        if not session or not session.get("handshake_complete"):
            raise ValueError(f"No established session with {client_name}")

        old_kc = session["keys"]["kc_to_s"]
        old_ks = session["keys"]["ks_to_c"]
        session["keys"]["kc_to_s"] = self._update_traffic_keys(old_kc)
        session["keys"]["ks_to_c"] = self._update_traffic_keys(old_ks)
        print(f"  Server: Traffic keys updated for {client_name}")

        return {"type": "KeyUpdate", "update_requested": update_requested}

    def receive_key_update(self, client_name: str) -> bool:
        session = self.sessions.get(client_name)
        if not session or not session.get("handshake_complete"):
            return False

        old_kc = session["keys"]["kc_to_s"]
        old_ks = session["keys"]["ks_to_c"]
        session["keys"]["kc_to_s"] = self._update_traffic_keys(old_kc)
        session["keys"]["ks_to_c"] = self._update_traffic_keys(old_ks)
        print(f"  Server: Keys updated in response to {client_name}'s KeyUpdate")
        return True
