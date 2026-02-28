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

    member1 = Member(name="Alice", ca=ca)
    member2 = Member(name="Bob", ca=ca)
    member3 = Member(name="Eve", ca=ca)

    print(f"Member 1: {member1.name}")
    print(f"Member 1 public key: {member1.public_key.hex()[:32]}...")

    print(f"Member 2: {member2.name}")
    print(f"Member 2 public key: {member2.public_key.hex()[:32]}...")

    print(f"Member 3: {member3.name}")
    print(f"Member 3 public key: {member3.public_key.hex()[:32]}...")

    print("\n" + "=" * 80)
    print(" " * 25 + "STEP 3: REQUEST CERTIFICATES")
    print("=" * 80)

    cert1 = member1.request_certificate()
    cert2 = member2.request_certificate()
    cert3 = member3.request_certificate()

    print(f"\n{member1.name} certificate:")
    print(f"  Serial: {cert1['serial_number']}")
    print(f"  Valid from: {cert1['validity']['not_before']}")
    print(f"  Valid until: {cert1['validity']['not_after']}")

    print(f"\n{member2.name} certificate:")
    print(f"  Serial: {cert2['serial_number']}")
    print(f"  Valid from: {cert2['validity']['not_before']}")
    print(f"  Valid until: {cert2['validity']['not_after']}")

    print(f"\n{member3.name} certificate:")
    print(f"  Serial: {cert3['serial_number']}")
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
    print(" " * 25 + "STEP 5: SIGN AND VERIFY DATA")
    print("=" * 80)

    message = b"Hello from Alice!"
    print(f"\n{member1.name} signs: {message.decode()}")

    signature = member1.sign_data(message)
    print(f"Signature: {signature.hex()[:64]}...")

    print(f"\n{member2.name} verifies {member1.name}'s signature...")
    is_valid = member2.verify_with_cert(message, signature, member1.name)
    print(f"Result: {is_valid}")

    print(f"\n{member3.name} tries to forge a message...")
    forged_message = b"Hello from Alice!"
    forged_signature = member3.sign_data(forged_message)

    print(f"{member2.name} verifies forged signature...")
    is_forged_valid = member2.verify_with_cert(forged_message, forged_signature, member1.name)
    print(f"Forged signature valid: {is_forged_valid}")

    print("\n" + "=" * 80)
    print(" " * 25 + "STEP 6: CERTIFICATE REVOCATION")
    print("=" * 80)

    print(f"\nCA revokes {member3.name}'s certificate...")
    ca.revoke_certificate(cert3['serial_number'], reason="KEY COMPROMISE")

    print(f"\nVerifying {member3.name}'s certificate after revocation...")
    valid3_after, msg3_after = ca.verify_certificate(cert3)
    print(f"{member3.name}: {msg3_after} (Valid: {valid3_after})")

    print(f"\nCertificate Revocation List (CRL):")
    crl = ca.get_crl()
    print(f"  Issuer: {crl['issuer']}")
    print(f"  Revoked certificates: {len(crl['revoked_certificates'])}")
    for entry in crl['revoked_certificates']:
        print(f"    - Serial {entry['serial_number']}: {entry['reason']}")

    message_after_revocation = b"Hello from Eve (after revocation)!"
    signature_after_revocation = member3.sign_data(message_after_revocation)

    print(f"\n{member2.name} verifies {member3.name}'s signature after revocation...")
    is_after_revocation_valid = member2.verify_with_cert(
        message_after_revocation,
        signature_after_revocation,
        member3.name
    )
    print(f"Signature valid after revocation: {is_after_revocation_valid}")

    print("\n" + "=" * 80)
    print(" " * 25 + "STEP 7: SAVE DATA TO FILES")
    print("=" * 80)

    ca.save_to_files()
    print("\nFiles saved:")
    print(f"  - {ca.ca_info_file}")
    print(f"  - {ca.repo_file}")
    print(f"  - {ca.crl_file}")


if __name__ == "__main__":
    main()