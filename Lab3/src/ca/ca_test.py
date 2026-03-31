from ca import CertificateAuthority
import gostcrypto

def main():

    print(f"{80 * '='}")
    print(f"{' '*20}BASIC CA SIGNING TEST")
    print(f"{80 * '='}")

    # 1) Base features
    # Init CA
    ca = CertificateAuthority(name="Test-CA")

    # Some Plain Text
    data = b"Template Message"

    # Signature
    singature = ca.sign_data(data_bytes=data)

    # Public key
    ca_public_key = ca.ca_public_key

    # verification
    is_valid = ca.verify_signature(data_bytes=data, signature=singature, public_key=ca_public_key)

    print(f"{' '*20}Signed by CA? - {is_valid}")

    print(f"{80 * '='}")
    print(f"{' '*20}CA CETRIFICATES CREATION TEST")
    print(f"{80 * '='}\n")

    # Generating public keys for members
    sign_obj = gostcrypto.gostsignature.new(
        gostcrypto.gostsignature.MODE_256,
        ca.curve
    )

    member1_key = bytearray([0x11] * 32)
    member1_pub = sign_obj.public_key_generate(member1_key)

    member2_key = bytearray([0x11] * 32)
    member2_pub = sign_obj.public_key_generate(member2_key)

    # Creating certificates
    cert1 = ca.create_certificate("Membder_1", member1_pub)
    cert2 = ca.create_certificate("Membder_2", member2_pub)

    print(f"{80 * '='}")
    print(f"{' '*20}CHECKING OF CERTIFICATES SIGNED")
    print(f"{80 * '='}")

    valid1, msg1 = ca.verify_certificate(cert1)
    print(f"\n{' '*20}Member_1 Valid?: {valid1}")
    print(f"{' '*20}Member_1: {msg1}\n")

    valid2, msg2 = ca.verify_certificate(cert2)
    print(f"{' '*20}Member_2 Valid?: {valid2}")
    print(f"{' '*20}Member_2: {msg2}\n")

    print(f"{80 * '='}")
    print(f"{' '*20}ANNULATION CHECK")
    print(f"{80 * '='}")

    print(f"\n{' '*20}Member_1:")
    ca.revoke_certificate(1, "KEY COMPROMISE")

    print(f"\n{80 * '='}")
    print(f"{' '*20}AFTER ANNULATION CHECK")
    print(f"{80 * '='}")

    valid1, msg1 = ca.verify_certificate(cert1)
    print(f"\n{' '*20}Member_1 Valid?: {valid1}")
    print(f"{' '*20}Member_1: {msg1}\n")

    print(f"{80 * '='}")
    print(f"{' '*20}SAVING FILES")
    print(f"{80 * '='}\n")
    ca.save_to_files()

    print(f"{80 * '='}")
    print(f"{' '*20}CHECK FOR ANNULATED")
    print(f"{80 * '='}")

    crl = ca.get_crl()  
    print(f"{' '*20}Annulated: {len(crl['revoked_certificates'])}")    

    print("\n" + "=" * 80)
    print(f"{' '*20}READY!")

     








if __name__ == "__main__":
    main()

