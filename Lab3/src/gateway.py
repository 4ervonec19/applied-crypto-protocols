import gostcrypto
from ida.ida import decode
from ca.ca import CertificateAuthority
from ca.member import Member
from storage_node import StorageNode


class Gateway:
    def __init__(self, ca, member, storage_nodes: list) -> None:
        """
        params:
            ca: Certification Authority
            member: Member instance (Gateway)
            storage_nodes: list of StorageNode instances
        """
        self.ca = ca
        self.member = member
        self.storage_nodes = storage_nodes

        self.m = storage_nodes[0].m if storage_nodes else 3
        self.n = storage_nodes[0].n if storage_nodes else 5

        # Хранилище метаданных: user_subject → list of file hashes
        self.user_files = {}

    def deposit(self, file_data: bytes, user_signature: bytes, user_cert: dict) -> dict:
        """
        Deposit protocol: store file to distributed storage

        params:
            file_data: file to store
            user_signature: Sign_U(F)
            user_cert: user certificate

        returns:
            dict with success status and signature
        """
        is_valid = self.member.verify_with_cert(
            file_data, 
            user_signature, 
            user_cert['subject']
        )

        if not is_valid:
            print("[GW]: User signature invalid!")
            return {"success": False, "message": "Invalid user signature"}

        for node in self.storage_nodes:
            success = node.receive_file(file_data, user_signature, user_cert)
            if not success:
                print(f"[GW]: Node {node.node_id} rejected file!")

        file_hash = gostcrypto.gosthash.new('streebog256', data=file_data).digest()

        confirmations = []
        for node in self.storage_nodes:
            conf = node.sign_confirmation(user_cert['subject'], file_hash)
            confirmations.append((node.node_id, conf))

        # Подпись подтверждения Gateway
        data_to_sign = user_cert['subject'].encode('utf-8') + file_hash
        gw_signature = self.member.sign_data(data_to_sign)

        # Сохраняем хэш файла за пользователем
        user_subject = user_cert['subject']
        if user_subject not in self.user_files:
            self.user_files[user_subject] = []
        if file_hash not in self.user_files[user_subject]:
            self.user_files[user_subject].append(file_hash)

        return {
            "success": True,
            "signature": gw_signature,
            "confirmations": confirmations
        }

    def retrieve(self, user_signature: bytes, user_cert: dict, file_hash: bytes) -> dict:
        """
        Retrieval protocol: restore file from distributed storage

        params:
            user_signature: Sign_U(H(F))
            user_cert: user certificate
            file_hash: H(F) for checking the signature

        returns:
            dict with success status and recovered file
        """
        user_subject = user_cert['subject']

        # Check 1: Does user own this file?
        if user_subject not in self.user_files:
            print(f"[GW]: User '{user_subject}' has no files in storage!")
            return {"success": False, "message": "User has no files"}

        if file_hash not in self.user_files[user_subject]:
            print(f"[GW]: File not found for user '{user_subject}'!")
            return {"success": False, "message": "File not found for this user"}

        # Check 2: User signature
        is_valid = self.member.verify_with_cert(
            file_hash,           # Data (Hash)
            user_signature,      # Signature
            user_subject
        )

        if not is_valid:
            print("[GW]: User signature invalid!")
            return {"success": False, "message": "Invalid user signature"}

        fragments = []
        all_hashes = []

        for node in self.storage_nodes:
            frag = node.get_fragment()
            hashes = node.get_all_hashes()
            fragments.append(frag)
            all_hashes.append(hashes)

        correct_hashes = {}
        for i in range(self.n):
            hash_counts = {}
            for node_hashes in all_hashes:
                h = node_hashes.get(i)
                if h:
                    # Конвертируем bytearray в bytes для использования как ключ
                    h_bytes = bytes(h) if isinstance(h, bytearray) else h
                    hash_counts[h_bytes] = hash_counts.get(h_bytes, 0) + 1
            correct_hashes[i] = max(hash_counts, key=hash_counts.get)

        available_fragments = []
        for i, frag in enumerate(fragments):
            if frag is None:
                available_fragments.append(None)
                continue

            actual_hash = gostcrypto.gosthash.new('streebog256', data=frag).digest()
            expected_hash = correct_hashes[i]

            # Конвертируем для сравнения
            actual_hash_bytes = bytes(actual_hash) if isinstance(actual_hash, bytearray) else actual_hash
            expected_hash_bytes = bytes(expected_hash) if isinstance(expected_hash, bytearray) else expected_hash

            if actual_hash_bytes == expected_hash_bytes:
                available_fragments.append(frag)
            else:
                print(f"[GW]: Fragment {i} hash mismatch!")
                available_fragments.append(None)

        try:
            recovered_file = decode(available_fragments, self.m, self.n)
            return {"success": True, "file": recovered_file}
        except Exception as e:
            print(f"[GW]: Decode error: {e}")
            return {"success": False, "message": str(e)}


if __name__ == "__main__":
    print("=" * 70)
    print(" " * 25 + "GATEWAY TEST")
    print("=" * 70)

    # Create CA
    print("\n[1] Creating CA...")
    ca = CertificateAuthority(name="Test-CA-GW")
    print(f"    CA created: {ca.name}")

    # Create storage nodes V1..V5
    print("\n[2] Creating storage nodes...")
    nodes = []
    for i in range(1, 6):
        node_member = Member(name=f"V{i}", ca=ca, scheme=Member.SCHEME_GOST)
        node_member.request_certificate()
        node = StorageNode(node_id=i, ca=ca, member=node_member)
        nodes.append(node)
        print(f"    V{i} created")

    # Create Gateway
    print("\n[3] Creating Gateway...")
    gw_member = Member(name="Gateway", ca=ca, scheme=Member.SCHEME_GOST)
    gw_member.request_certificate()
    gw = Gateway(ca=ca, member=gw_member, storage_nodes=nodes)
    print(f"    Gateway created (m={gw.m}, n={gw.n})")

    # Create User
    print("\n[4] Creating User...")
    user = Member(name="User", ca=ca, scheme=Member.SCHEME_GOST)
    user.request_certificate()
    print(f"    User created")

    # Test file
    print("\n[5] Test file...")
    test_file = b"Test file for Gateway deposit and retrieval protocol"
    print(f"    Size: {len(test_file)} bytes")
    print(f"    Content: {test_file}")

    # User signs file
    print("\n[6] User signs file...")
    user_sig = user.sign_data(test_file)
    print(f"    Signature: {user_sig.hex()[:40]}...")

    # DEPOSIT
    print("\n[7] DEPOSIT protocol...")
    deposit_result = gw.deposit(test_file, user_sig, user.certificate)
    print(f"    Success: {deposit_result['success']}")
    print(f"    Confirmations: {len(deposit_result['confirmations'])}")

    # RETRIEVAL
    print("\n[8] RETRIEVAL protocol...")
    test_file_hash = gostcrypto.gosthash.new('streebog256', data=test_file).digest()
    user_sig_retrieve = user.sign_data(test_file_hash)
    retrieve_result = gw.retrieve(user_sig_retrieve, user.certificate, test_file_hash)

    if retrieve_result['success']:
        recovered = retrieve_result['file']
        print(f"    Success: True")
        print(f"    Original:  {test_file}")
        print(f"    Recovered: {recovered}")
        print(f"    Match: {test_file == recovered}")
    else:
        print(f"    Success: False")
        print(f"    Message: {retrieve_result['message']}")

    # Test with lost nodes
    print("\n[9] RETRIEVAL with lost nodes (V2, V4 offline)...")
    nodes[1].fragment = None  # V2 lost
    nodes[3].fragment = None  # V4 lost

    user_sig_retrieve2 = user.sign_data(test_file_hash)
    retrieve_result2 = gw.retrieve(user_sig_retrieve2, user.certificate, test_file_hash)

    if retrieve_result2['success']:
        recovered2 = retrieve_result2['file']
        print(f"    Success: True")
        print(f"    Match: {test_file == recovered2}")
    else:
        print(f"    Success: False")
        print(f"    Message: {retrieve_result2['message']}")

    print("\n" + "=" * 70)
    print(" " * 25 + "TEST COMPLETE")
    print("=" * 70)
