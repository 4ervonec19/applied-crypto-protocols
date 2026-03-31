from ca.ca import CertificateAuthority
from ca.member import Member
from storage_node import StorageNode
from gateway import Gateway
from user import User
import gostcrypto

def scenario_1_successful_recovery():
    print("CASE 1: SUCCESSFUL UPLOAD AND RECOVERY")
    
    ca = CertificateAuthority(name="Lab3-CA-Scenario1")
    
    nodes = []
    for i in range(1, 6):
        node_member = Member(name=f"V{i}", ca=ca, scheme=Member.SCHEME_GOST)
        node_member.request_certificate()
        node = StorageNode(node_id=i, ca=ca, member=node_member)
        nodes.append(node)
    
    gw_member = Member(name="Gateway", ca=ca, scheme=Member.SCHEME_GOST)
    gw_member.request_certificate()
    gw = Gateway(ca=ca, member=gw_member, storage_nodes=nodes)
    
    alice_member = Member(name="Alice", ca=ca, scheme=Member.SCHEME_GOST)
    alice_member.request_certificate()
    alice = User(ca=ca, member=alice_member)
    
    print("Step 1: Alice uploads file")
    original_file = b"CONFIDENTIAL: Alice's tax documents. Private."
    print(f"Original file: {original_file}")
    
    file_hash = gostcrypto.gosthash.new('streebog256', data=original_file).digest()
    upload_sig = alice.sign_file(original_file)
    
    deposit_result = gw.deposit(original_file, upload_sig, alice_member.certificate)
    print(f"Upload success: {deposit_result['success']}")
    print(f"Stored on {len(nodes)} nodes")
    
    print("Step 2: Alice deletes local copy")
    del original_file
    print("Local file: DELETED")
    print(f"Alice only has: file hash = {file_hash.hex()[:32]}...")
    
    print("Step 3: Alice recovers file (no original)")
    
    request_sig = alice.sign_request_by_hash(file_hash)
    recover_result = gw.retrieve(request_sig, alice_member.certificate, file_hash)
    
    if recover_result['success']:
        recovered_file = recover_result['file']
        print(f"Recovery success: True")
        print(f"Recovered file: {recovered_file}")
        
        is_valid = alice.verify_restored_file_by_hash(recovered_file, file_hash)
        print(f"Integrity check: {'PASS - Files match!' if is_valid else 'FAIL - Files differ!'}")
    else:
        print(f"Recovery failed: {recover_result['message']}")
    
    return recover_result['success'] and is_valid


def scenario_2_access_denied():
    print("CASE 2: BOB TRIES TO ACCESS ALICE'S FILE")
    
    ca = CertificateAuthority(name="Lab3-CA-Scenario2")
    
    nodes = []
    for i in range(1, 6):
        node_member = Member(name=f"V{i}", ca=ca, scheme=Member.SCHEME_GOST)
        node_member.request_certificate()
        node = StorageNode(node_id=i, ca=ca, member=node_member)
        nodes.append(node)
    
    gw_member = Member(name="Gateway", ca=ca, scheme=Member.SCHEME_GOST)
    gw_member.request_certificate()
    gw = Gateway(ca=ca, member=gw_member, storage_nodes=nodes)
    
    alice_member = Member(name="Alice", ca=ca, scheme=Member.SCHEME_GOST)
    alice_member.request_certificate()
    alice = User(ca=ca, member=alice_member)
    
    bob_member = Member(name="Bob", ca=ca, scheme=Member.SCHEME_GOST)
    bob_member.request_certificate()
    bob = User(ca=ca, member=bob_member)
    
    print("Step 1: Alice uploads her file")
    
    alice_file = b"Alice's private medical records. Diagnosis: Confidential."
    print(f"Alice's file: {alice_file}")
    
    alice_hash = gostcrypto.gosthash.new('streebog256', data=alice_file).digest()
    alice_sig = alice.sign_file(alice_file)
    
    deposit_result = gw.deposit(alice_file, alice_sig, alice_member.certificate)
    print(f"Alice's upload success: {deposit_result['success']}")
    
    print("Step 2: Bob uploads his own file")
    
    bob_file = b"Bob's personal notes. Nothing secret."
    print(f"Bob's file: {bob_file}")
    
    bob_hash = gostcrypto.gosthash.new('streebog256', data=bob_file).digest()
    bob_sig = bob.sign_file(bob_file)
    
    bob_deposit = gw.deposit(bob_file, bob_sig, bob_member.certificate)
    print(f"Bob's upload success: {bob_deposit['success']}")
    
    print("Step 3: Bob tries to steal Alice's file")
    
    print(f"Bob knows Alice's file hash: {alice_hash.hex()[:32]}...")
    print("Bob signs request for Alice's file hash...")
    
    bob_request_sig = bob.sign_request_by_hash(alice_hash)
    bob_result = gw.retrieve(bob_request_sig, bob_member.certificate, alice_hash)
    
    if bob_result['success']:
        print(f"SECURITY BREACH! Bob recovered Alice's file!")
        print(f"Bob got: {bob_result['file']}")
        return False
    else:
        print(f"ACCESS DENIED! Bob cannot get Alice's file")
        print(f"Gateway message: {bob_result['message']}")
    
    print("Step 4: Bob recovers his own file")
    
    bob_recover_sig = bob.sign_request_by_hash(bob_hash)
    bob_recover_result = gw.retrieve(bob_recover_sig, bob_member.certificate, bob_hash)
    
    if bob_recover_result['success']:
        print(f"Bob recovered his own file: {bob_recover_result['file']}")
        return True
    else:
        print(f"Bob failed to recover his own file: {bob_recover_result['message']}")
        return False


def scenario_3_node_compromise():
    print("CASE 3: NODE COMPROMISE - DATA TAMPERING DETECTED")
    
    ca = CertificateAuthority(name="Lab3-CA-Scenario3")
    
    nodes = []
    for i in range(1, 6):
        node_member = Member(name=f"V{i}", ca=ca, scheme=Member.SCHEME_GOST)
        node_member.request_certificate()
        node = StorageNode(node_id=i, ca=ca, member=node_member)
        nodes.append(node)
    
    gw_member = Member(name="Gateway", ca=ca, scheme=Member.SCHEME_GOST)
    gw_member.request_certificate()
    gw = Gateway(ca=ca, member=gw_member, storage_nodes=nodes)
    
    alice_member = Member(name="Alice", ca=ca, scheme=Member.SCHEME_GOST)
    alice_member.request_certificate()
    alice = User(ca=ca, member=alice_member)
    
    print("Step 1: Alice uploads file")
    
    original_file = b"IMPORTANT: Business contract. Value: $500,000. Terms: Confidential."
    print(f"Original file: {original_file}")
    
    file_hash = gostcrypto.gosthash.new('streebog256', data=original_file).digest()
    upload_sig = alice.sign_file(original_file)
    
    deposit_result = gw.deposit(original_file, upload_sig, alice_member.certificate)
    print(f"Upload success: {deposit_result['success']}")
    print(f"File stored on nodes V1, V2, V3, V4, V5")
    
    print("Step 2: Hacker compromises node V3")
    
    original_v3_fragment = nodes[2].fragment
    tampered_fragment = b"HACKED: Contract value changed to $1!" + nodes[2].fragment[35:]
    nodes[2].fragment = tampered_fragment
    
    print(f"V3 fragment tampered!")
    print(f"Original: {original_v3_fragment[:30]}...")
    print(f"Tampered: {tampered_fragment[:30]}...")
    
    print("Step 3: Alice recovers file (Gateway detects tampering)")
    
    request_sig = alice.sign_request_by_hash(file_hash)
    recover_result = gw.retrieve(request_sig, alice_member.certificate, file_hash)
    
    if recover_result['success']:
        recovered_file = recover_result['file']
        print(f"Recovery success: True")
        print(f"Recovered file: {recovered_file}")
        
        is_valid = alice.verify_restored_file_by_hash(recovered_file, file_hash)
        
        if is_valid:
            print(f"Integrity check: PASS")
            print(f"Gateway detected tampered node and excluded it!")
            print(f"File recovered from honest nodes (V1, V2, V4, V5)")
        else:
            print(f"Integrity check: FAIL - File was corrupted!")
        
        return is_valid
    else:
        print(f"Recovery failed: {recover_result['message']}")
        return False


def main():
    print("=" * 80)
    print(" " * 10 + "LAB 3: DISTRIBUTED SECURE STORAGE - DEMONSTRATION")
    print("=" * 80)
    
    results = []
    
    print("\n")
    print("=" * 80)
    result1 = scenario_1_successful_recovery()
    results.append(("Successful recovery", result1))
    print("=" * 80)
    print("\n")
    
    print("\n")
    print("=" * 80)
    result2 = scenario_2_access_denied()
    results.append(("Access control (Bob denied)", result2))
    print("=" * 80)
    print("\n")
    
    print("\n")
    print("=" * 80)
    result3 = scenario_3_node_compromise()
    results.append(("Node compromise detection", result3))
    print("=" * 80)
    print("\n")
    
if __name__ == "__main__":
    main()
