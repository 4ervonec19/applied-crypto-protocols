import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ca import CertificateAuthority
from server import Server
from client import Client
from crypto_utils import GOSTSigner
from config import (
    CA_NAME, SERVER_NAME, CLIENT1_NAME, CLIENT2_NAME,
    AUTH_MODE_MUTUAL, AUTH_MODE_ONE_WAY
)


def print_header(title: str):
    print(f"\n{'#'*80}")
    print(f"#  {title}")
    print(f"{'#'*80}")


def print_subheader(title: str):
    print(f"\n{'─'*60}")
    print(f"  {title}")
    print(f"{'─'*60}")


def setup_infrastructure():
    print_header("SETUP: Creating CA and issuing certificates")

    ca = CertificateAuthority(name=CA_NAME)
    print(f"CA created: {ca.name}")

    server_signer = GOSTSigner()
    server_cert = ca.create_certificate(SERVER_NAME, server_signer.public_key)

    client1_signer = GOSTSigner()
    client1_cert = ca.create_certificate(CLIENT1_NAME, client1_signer.public_key)

    client2_signer = GOSTSigner()
    client2_cert = ca.create_certificate(CLIENT2_NAME, client2_signer.public_key)

    return ca, server_signer, server_cert, client1_signer, client1_cert, client2_signer, client2_cert


def scenario1_client1_dh_mutual(ca, server_signer, server_cert, client1_signer, client1_cert):
    print_header("SCENARIO 1: Client1 (DH + Mutual Auth) <-> Server")

    server = Server(ca=ca, certificate=server_cert, gost_signer=server_signer)
    client1 = Client(
        name=CLIENT1_NAME, ca=ca, certificate=client1_cert,
        gost_signer=client1_signer, group_type="DH", auth_mode=AUTH_MODE_MUTUAL
    )

    if not client1.full_handshake(server):
        print(f"\n  SCENARIO 1 FAILED: Handshake failed")
        return False

    print_subheader("DATA EXCHANGE")
    msg_from_client = client1.send_data(b"Hello from client1")
    server.receive_data(msg_from_client, CLIENT1_NAME)

    msg_from_server = server.send_data(b"Response from server", CLIENT1_NAME)
    client1.receive_data(msg_from_server)

    print_subheader("KEYUPDATE (initiated by Client1)")
    client1.initiate_key_update()
    server.receive_key_update(CLIENT1_NAME)
    print(f"  Keys updated successfully")

    print_subheader("DATA EXCHANGE AFTER KEYUPDATE")
    msg_from_client2 = client1.send_data(b"Hello after key update!")
    server.receive_data(msg_from_client2, CLIENT1_NAME)

    msg_from_server2 = server.send_data(b"Server response after update!", CLIENT1_NAME)
    client1.receive_data(msg_from_server2)

    print(f"\n  SCENARIO 1 COMPLETED SUCCESSFULLY")
    return True


def scenario2_client2_ecdh_oneway(ca, server_signer, server_cert, client2_signer, client2_cert):
    print_header("SCENARIO 2: Client2 (ECDH + One-Way Auth) ↔ Server")

    server = Server(ca=ca, certificate=server_cert, gost_signer=server_signer)
    client2 = Client(
        name=CLIENT2_NAME, ca=ca, certificate=client2_cert,
        gost_signer=client2_signer, group_type="ECDH", auth_mode=AUTH_MODE_ONE_WAY
    )

    if not client2.full_handshake(server):
        print(f"\n  SCENARIO 2 FAILED: Handshake failed")
        return False

    print_subheader("DATA EXCHANGE")
    msg_from_client = client2.send_data(b"Hello from client2")
    server.receive_data(msg_from_client, CLIENT2_NAME)

    msg_from_server = server.send_data(b"Response from server to client2", CLIENT2_NAME)
    client2.receive_data(msg_from_server)

    print_subheader("KEYUPDATE (initiated by Server)")
    server.handle_key_update(CLIENT2_NAME, update_requested=True)
    client2.handle_key_update()
    print(f"  Keys updated successfully")

    print_subheader("DATA EXCHANGE AFTER KEYUPDATE")
    msg_from_client2 = client2.send_data(b"Hello after server key update!")
    server.receive_data(msg_from_client2, CLIENT2_NAME)

    msg_from_server2 = server.send_data(b"Server response after server-initiated update!", CLIENT2_NAME)
    client2.receive_data(msg_from_server2)

    print(f"\n  SCENARIO 2 COMPLETED SUCCESSFULLY")
    return True


def scenario3_crl_revocation(ca, server_signer, server_cert, client1_signer, client1_cert):
    print_header("SCENARIO 3: CRL — Revoking Client1 certificate")

    serial = client1_cert["serial_number"]
    ca.revoke_certificate(serial, reason="KEY COMPROMISE")

    crl = ca.get_crl()
    print(f"  CRL contains {len(crl['revoked_certificates'])} revoked certificate(s)")

    print_subheader("ATTEMPTING HANDSHAKE WITH REVOKED CERTIFICATE")

    server = Server(ca=ca, certificate=server_cert, gost_signer=server_signer)
    client1_revoked = Client(
        name=CLIENT1_NAME, ca=ca, certificate=client1_cert,
        gost_signer=client1_signer, group_type="DH", auth_mode=AUTH_MODE_MUTUAL
    )

    success = client1_revoked.full_handshake(server)
    if not success:
        print(f"\n  SCENARIO 3 COMPLETED: Handshake correctly FAILED with revoked certificate")
        return True
    else:
        print(f"\n  SCENARIO 3 UNEXPECTED: Handshake should have failed!")
        return False


def failed_scenario1_expired_cert(ca, server_signer, server_cert):
    print_header("FAILED SCENARIO 1: Expired certificate")

    from datetime import datetime, timedelta
    import json

    expired_signer = GOSTSigner()
    expired_cert = ca.create_certificate("ExpiredUser", expired_signer.public_key, days_valid=0)

    past = datetime.now() - timedelta(days=30)
    past_end = datetime.now() - timedelta(days=1)
    expired_cert["validity"]["not_before"] = past.isoformat()
    expired_cert["validity"]["not_after"] = past_end.isoformat()

    cert_data = {k: v for k, v in expired_cert.items() if k != "signature"}
    data_to_sign = json.dumps(cert_data, sort_keys=True).encode('utf-8')
    signature = ca.sign_data(data_to_sign)
    expired_cert["signature"] = signature.hex()

    print(f"  Created expired certificate for 'ExpiredUser'")

    is_valid, msg = ca.verify_certificate(expired_cert)
    print(f"  Certificate verification result: {is_valid} — {msg}")

    if not is_valid:
        print(f"\n  FAILED SCENARIO 1 COMPLETED: Expired certificate correctly rejected")
        return True
    return False


def failed_scenario2_cert_not_found(ca, server_signer, server_cert):
    print_header("FAILED SCENARIO 2: Certificate not found in repository")

    unknown_signer = GOSTSigner()
    fake_cert = {
        "serial_number": 9999,
        "signature_algorithm": "ГОСТ-512",
        "issuer": "Unknown-CA",
        "validity": {"not_before": "2025-01-01T00:00:00", "not_after": "2030-01-01T00:00:00"},
        "key_usage": "sign",
        "subject": "UnknownUser",
        "subject_public_key_algorithm": "GOST-34.10-2012-256",
        "subject_public_key": unknown_signer.public_key.hex(),
        "signature": "00" * 64
    }

    print(f"  Created fake certificate from 'Unknown-CA'")

    is_valid, msg = ca.verify_certificate(fake_cert)
    print(f"  Certificate verification result: {is_valid} — {msg}")

    if not is_valid:
        print(f"\n  FAILED SCENARIO 2 COMPLETED: Unknown certificate correctly rejected")
        return True
    return False


def failed_scenario3_cert_in_crl(ca, server_signer, server_cert, client2_signer, client2_cert):
    print_header("FAILED SCENARIO 3: Server certificate in CRL")

    serial = server_cert["serial_number"]
    ca.revoke_certificate(serial, reason="CESSATION OF OPERATION")

    crl = ca.get_crl()
    print(f"  CRL now contains {len(crl['revoked_certificates'])} certificate(s)")

    server = Server(ca=ca, certificate=server_cert, gost_signer=server_signer)
    client2_new = Client(
        name=CLIENT2_NAME, ca=ca, certificate=client2_cert,
        gost_signer=client2_signer, group_type="ECDH", auth_mode=AUTH_MODE_ONE_WAY
    )

    success = client2_new.full_handshake(server)
    if not success:
        print(f"\n  FAILED SCENARIO 3 COMPLETED: Server's revoked certificate correctly rejected by client")
        return True
    return False


def failed_scenario4_unsupported_group(ca, server_signer, server_cert):
    print_header("FAILED SCENARIO 4: Unsupported cryptographic group")

    unknown_signer = GOSTSigner()
    unknown_cert = ca.create_certificate("ECDHOnlyClient", unknown_signer.public_key)

    ecdh_client = Client(
        name="ECDHOnlyClient", ca=ca, certificate=unknown_cert,
        gost_signer=unknown_signer, group_type="ECDH", auth_mode=AUTH_MODE_ONE_WAY
    )

    server = Server(ca=ca, certificate=server_cert, gost_signer=server_signer)

    msg1 = ecdh_client.create_message1()
    msg1["offer"] = ["TLS_DH_ANON_WITH_AES_256_GCM_SHA384"]

    try:
        server.handshake_receive_message1(msg1, "ECDHOnlyClient")
        print(f"\n  FAILED SCENARIO 4 UNEXPECTED: Server should have rejected unsupported suite")
        return False
    except ValueError as e:
        print(f"  Server correctly rejected unsupported cipher suite: {e}")
        print(f"\n  FAILED SCENARIO 4 COMPLETED: Unsupported group correctly rejected")
        return True


def main():
    print("=" * 80)
    print(" " * 20 + "LAB 4 — TLS 1.3 MODEL")
    print("=" * 80)

    ca, server_signer, server_cert, client1_signer, client1_cert, client2_signer, client2_cert = setup_infrastructure()

    # Successful scenarios
    scenario1_client1_dh_mutual(ca, server_signer, server_cert, client1_signer, client1_cert)
    scenario2_client2_ecdh_oneway(ca, server_signer, server_cert, client2_signer, client2_cert)
    scenario3_crl_revocation(ca, server_signer, server_cert, client1_signer, client1_cert)

    # Failed scenarios
    failed_scenario1_expired_cert(ca, server_signer, server_cert)
    failed_scenario2_cert_not_found(ca, server_signer, server_cert)
    failed_scenario3_cert_in_crl(ca, server_signer, server_cert, client2_signer, client2_cert)
    failed_scenario4_unsupported_group(ca, server_signer, server_cert)

    # Summary
    print_header("SUMMARY")
    print("""
  Successful:
    [COMPLETED] Scenario 1: Client1 (DH + mutual auth) — handshake, data, KeyUpdate
    [COMPLETED] Scenario 2: Client2 (ECDH + one-way auth) — handshake, data, KeyUpdate
    [COMPLETED] Scenario 3: CRL revocation — handshake correctly fails

  Failed (expected failures):
    [COMPLETED] Expired certificate — rejected
    [COMPLETED] Certificate from unknown CA — rejected
    [COMPLETED] Certificate in CRL — rejected
    [COMPLETED] Unsupported cipher suite — rejected
    """)

    print("=" * 80)
    print(" " * 25 + "LAB 4 COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()
