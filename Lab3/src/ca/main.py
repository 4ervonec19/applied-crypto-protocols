from ca import CertificateAuthority
from member import Member

def main():
    print("=" * 80)
    print(" " * 25 + "LAB-1 - PKI")
    print("=" * 80)

    print("\n" + "=" * 80)
    print(" " * 25 + "STEP 1: CREATE CA")
    print("=" * 80)

    ca = CertificateAuthority(name="Test-CA-lab-1")
    print(f"CA created: {ca.name}")
    print(f"CA public key: {ca.ca_public_key.hex()[:32]}...")

    print("\n" + "=" * 80)
    print(" " * 25 + "STEP 2: CREATE MEMBERS")
    print("=" * 80)

    # Alice uses GOST scheme (with ECDH for key exchange)
    member1 = Member(name="Alice", ca=ca, scheme=Member.SCHEME_GOST)
    # Bob uses RSA scheme (with ECDH for key exchange)
    member2 = Member(name="Bob", ca=ca, scheme=Member.SCHEME_RSA)
    # Eve uses GOST scheme (for revocation test)
    member3 = Member(name="Eve", ca=ca, scheme=Member.SCHEME_GOST)

    print(f"\n{member1.name} (GOST + ECDH):")
    print(f"  Signature public key size: {len(member1.public_key)} bytes")
    print(f"  Signature public key: {member1.public_key.hex()[:32]}...")
    ecdh_pub = member1.get_exchange_public_key()
    print(f"  ECDH public key size: {len(ecdh_pub.export_key(format='DER'))} bytes")

    print(f"\n{member2.name} (RSA + ECDH):")
    print(f"  Signature public key size: {len(member2.public_key)} bytes")
    print(f"  Signature public key: {member2.public_key.hex()[:32]}...")
    ecdh_pub = member2.get_exchange_public_key()
    print(f"  ECDH public key size: {len(ecdh_pub.export_key(format='DER'))} bytes")

    print(f"\n{member3.name} (GOST + ECDH):")
    print(f"  Public key size: {len(member3.public_key)} bytes")
    print(f"  Public key: {member3.public_key.hex()[:32]}...")

    print("\n" + "=" * 80)
    print(" " * 25 + "STEP 3: REQUEST CERTIFICATES")
    print("=" * 80)

    cert1 = member1.request_certificate()
    cert2 = member2.request_certificate()
    cert3 = member3.request_certificate()

    print(f"\n{member1.name} certificate:")
    print(f"  Serial: {cert1['serial_number']}")
    print(f"  Key Algorithm: {cert1['subject_public_key_algorithm']}")
    print(f"  Valid from: {cert1['validity']['not_before']}")
    print(f"  Valid until: {cert1['validity']['not_after']}")

    print(f"\n{member2.name} certificate:")
    print(f"  Serial: {cert2['serial_number']}")
    print(f"  Key Algorithm: {cert2['subject_public_key_algorithm']}")
    print(f"  Valid from: {cert2['validity']['not_before']}")
    print(f"  Valid until: {cert2['validity']['not_after']}")

    print(f"\n{member3.name} certificate:")
    print(f"  Serial: {cert3['serial_number']}")
    print(f"  Key Algorithm: {cert3['subject_public_key_algorithm']}")
    print(f"  Valid from: {cert3['validity']['not_before']}")
    print(f"  Valid until: {cert3['validity']['not_after']}")

    print("\n" + "=" * 80)
    print(" " * 25 + "STEP 4: VERIFY CERTIFICATES")
    print("=" * 80)

    valid1, msg1 = ca.verify_certificate(cert1)
    print(f"\n{member1.name}: {msg1} (Valid: {valid1})")

    valid2, msg2 = ca.verify_certificate(cert2)
    print(f"{member2.name}: {msg2} (Valid: {valid2})")

    valid3, msg3 = ca.verify_certificate(cert3)
    print(f"{member3.name}: {msg3} (Valid: {valid3})")

    print("\n" + "=" * 80)
    print(" " * 25 + "STEP 5: SIGN AND VERIFY DATA (Cross-Scheme)")
    print("=" * 80)

    # Alice (GOST) signs, Bob (RSA) verifies
    message = b"Hello from Alice!"
    print(f"\n{member1.name} (GOST) signs: {message.decode()}")

    signature = member1.sign_data(message)
    print(f"Signature ({len(signature)} bytes): {signature.hex()[:64]}...")

    print(f"\n{member2.name} (RSA) verifies {member1.name}'s signature...")
    is_valid = member2.verify_with_cert(message, signature, member1.name)
    print(f"Result: {is_valid}")

    # Bob (RSA) signs, Alice (GOST) verifies
    message2 = b"Hello from Bob!"
    print(f"\n{member2.name} (RSA) signs: {message2.decode()}")

    signature2 = member2.sign_data(message2)
    print(f"Signature ({len(signature2)} bytes): {signature2.hex()[:64]}...")

    print(f"\n{member1.name} (GOST) verifies {member2.name}'s signature...")
    is_valid2 = member1.verify_with_cert(message2, signature2, member2.name)
    print(f"Result: {is_valid2}")

    print("\n" + "=" * 80)
    print(" " * 25 + "STEP 6: ECDH KEY EXCHANGE + ENCRYPTION")
    print("=" * 80)

    # Verify certificates before key exchange
    print(f"\nVerifying certificates before ECDH key exchange...")
    valid1, msg1 = ca.verify_certificate(cert1)
    valid2, msg2 = ca.verify_certificate(cert2)
    print(f"  {member1.name}: {msg1} (Valid: {valid1})")
    print(f"  {member2.name}: {msg2} (Valid: {valid2})")

    # Alice computes shared secret (with certificate verification)
    print(f"\n{member1.name} computes shared secret (with cert verification)...")
    alice_shared = member1.compute_shared_secret_with_cert_verify(member2)
    if alice_shared:
        print(f"  Alice's shared secret: {alice_shared.hex()}")

    # Bob computes shared secret (with certificate verification)
    print(f"\n{member2.name} computes shared secret (with cert verification)...")
    bob_shared = member2.compute_shared_secret_with_cert_verify(member1)
    if bob_shared:
        print(f"  Bob's shared secret:   {bob_shared.hex()}")

    if alice_shared and bob_shared:
        print(f"\nShared secrets match: {alice_shared == bob_shared}")

        # ENCRYPTION TEST
        print("\n" + "-" * 80)
        print(" " * 20 + "ENCRYPTION / DECRYPTION TEST")
        print("-" * 80)

        # Alice encrypts a message using the shared secret
        secret_message = b"Top secret message from Alice to Bob!"
        print(f"\n{member1.name} encrypts: {secret_message.decode()}")
        encrypted = member1.encrypt_with_shared_secret(secret_message, alice_shared)
        print(f"Encrypted ({len(encrypted)} bytes): {encrypted.hex()[:64]}...")

        # Bob decrypts the message using the same shared secret
        print(f"\n{member2.name} decrypts the message...")
        decrypted = member2.decrypt_with_shared_secret(encrypted, bob_shared)
        print(f"Decrypted: {decrypted.decode()}")

        print(f"\nDecryption successful: {decrypted == secret_message}")

        # Bob encrypts a response
        response_message = b"Secret response from Bob to Alice!"
        print(f"\n{member2.name} encrypts: {response_message.decode()}")
        bob_encrypted = member2.encrypt_with_shared_secret(response_message, bob_shared)
        print(f"Encrypted ({len(bob_encrypted)} bytes): {bob_encrypted.hex()[:64]}...")

        # Alice decrypts the response
        print(f"\n{member1.name} decrypts the response...")
        alice_decrypted = member1.decrypt_with_shared_secret(bob_encrypted, alice_shared)
        print(f"Decrypted: {alice_decrypted.decode()}")

        print(f"\nDecryption successful: {alice_decrypted == response_message}")

    print("\n" + "=" * 80)
    print(" " * 25 + "STEP 7: CERTIFICATE REVOCATION (Protocol)")
    print("=" * 80)

    print(f"\n{member3.name} requests revocation of own certificate...")
    revocation_result = member3.request_revocation(reason="KEY COMPROMISE")

    print(f"\nVerifying {member3.name}'s certificate after revocation...")
    valid3_after, msg3_after = ca.verify_certificate(cert3)
    print(f"{member3.name}: {msg3_after} (Valid: {valid3_after})")

    print(f"\nCertificate Revocation List (CRL):")
    crl = ca.get_crl()
    print(f"  Issuer: {crl['issuer']}")
    print(f"  Revoked certificates: {len(crl['revoked_certificates'])}")
    for entry in crl['revoked_certificates']:
        print(f"    - Serial {entry['serial_number']}: {entry['reason']}")

    print("\n" + "=" * 80)
    print(" " * 25 + "STEP 8: SAVE DATA TO FILES")
    print("=" * 80)

    ca.save_to_files()
    print("\nFiles saved:")
    print(f"  - {ca.ca_info_file}")
    print(f"  - {ca.repo_file}")
    print(f"  - {ca.crl_file}")

    print("\n" + "=" * 80)
    print(" " * 25 + "READY!")
    print("=" * 80)


if __name__ == "__main__":
    main()
