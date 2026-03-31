import gostcrypto


class User:
    def __init__(self, ca, member) -> None:
        """
        params:
            ca: Certification Authority
            member: Member instance (User)
        """
        self.ca = ca
        self.member = member

    def sign_file(self, file_data: bytes) -> bytes:
        """
        Sign file for deposit protocol

        params:
            file_data: file to sign

        returns:
            signature Sign_U(F)
        """
        return self.member.sign_data(file_data)

    def sign_request(self, file_data: bytes) -> bytes:
        """
        Sign retrieval request by file hash

        params:
            file_data: original file (для вычисления хэша)

        returns:
            signature Sign_U(H(F))
        """
        file_hash = gostcrypto.gosthash.new('streebog256', data=file_data).digest()
        return self.member.sign_data(file_hash)

    def sign_request_by_hash(self, file_hash: bytes) -> bytes:
        """
        Sign retrieval request when file is NOT available locally.
        User only needs to remember the file hash.

        params:
            file_hash: H(F) from user's records

        returns:
            signature Sign_U(H(F))
        """
        return self.member.sign_data(file_hash)

    def verify_restored_file(self, original_file: bytes, restored_file: bytes) -> bool:
        """
        Verify that restored file matches original

        params:
            original_file: original file (or its hash)
            restored_file: file received from Gateway

        returns:
            True if files match
        """
        # Compare hashes
        original_hash = gostcrypto.gosthash.new('streebog256', data=original_file).digest()
        restored_hash = gostcrypto.gosthash.new('streebog256', data=restored_file).digest()

        return original_hash == restored_hash

    def verify_restored_file_by_hash(self, restored_file: bytes, expected_hash: bytes) -> bool:
        """
        Verify restored file when original is NOT available.
        Only compares hash of restored file with stored hash.

        params:
            restored_file: file received from Gateway
            expected_hash: H(F) from user's records

        returns:
            True if hashes match
        """
        restored_hash = gostcrypto.gosthash.new('streebog256', data=restored_file).digest()
        return restored_hash == expected_hash


if __name__ == "__main__":
    from ca.ca import CertificateAuthority
    from ca.member import Member
    from gateway import Gateway
    from storage_node import StorageNode

    print("=" * 70)
    print(" " * 25 + "USER TEST")
    print("=" * 70)

    # Setup
    ca = CertificateAuthority(name="Test-CA-User")

    # Create nodes
    nodes = []
    for i in range(1, 6):
        node_member = Member(name=f"V{i}", ca=ca, scheme=Member.SCHEME_GOST)
        node_member.request_certificate()
        node = StorageNode(node_id=i, ca=ca, member=node_member)
        nodes.append(node)

    # Create Gateway
    gw_member = Member(name="Gateway", ca=ca, scheme=Member.SCHEME_GOST)
    gw_member.request_certificate()
    gw = Gateway(ca=ca, member=gw_member, storage_nodes=nodes)

    # Create User
    print("\n[1] Creating User...")
    user_member = Member(name="Alice", ca=ca, scheme=Member.SCHEME_GOST)
    user_member.request_certificate()
    user = User(ca=ca, member=user_member)
    print(f"    User created: {user.member.name}")

    # Test file
    test_file = b"Confidential document: User test file for Lab 3"
    print(f"\n[2] Test file: {test_file}")

    # Deposit
    print("\n[3] DEPOSIT: User signs and sends file...")
    user_sig = user.sign_file(test_file)
    print(f"    Signature: {user_sig.hex()[:40]}...")

    deposit_result = gw.deposit(test_file, user_sig, user.member.certificate)
    print(f"    Gateway response: {deposit_result['success']}")

    # Retrieval
    print("\n[4] RETRIEVAL: User requests file...")
    file_hash = gostcrypto.gosthash.new('streebog256', data=test_file).digest()
    request_sig = user.sign_request(test_file)
    retrieve_result = gw.retrieve(request_sig, user.member.certificate, file_hash)

    if retrieve_result['success']:
        restored = retrieve_result['file']
        print(f"    File received from Gateway")

        # Verify
        is_match = user.verify_restored_file(test_file, restored)
        print(f"    Verification: {'MATCH ✓' if is_match else 'MISMATCH ✗'}")
    else:
        print(f"    Error: {retrieve_result['message']}")

    print("\n" + "=" * 70)
    print(" " * 25 + "TEST COMPLETE")
    print("=" * 70)
