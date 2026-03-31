import gostcrypto
from ida.ida import encode

class StorageNode:
    def __init__(self, node_id: int, ca, member) -> None:
        """
        params:
            node_id (int): id of storage node
            ca: Certification Authority (check certificates)
            member: Member instance
        """
        self.node_id = node_id
        self.ca = ca
        self.member = member
        self.m = 3
        self.n = 5

        self.fragment = None
        self.all_hashes = {}   
        self.user_signature = None
        self.original_file_hash = None
    
    def receive_file(self, file_data: bytes, user_signature: bytes, user_cert: dict):

        is_valid = self.member.verify_with_cert(file_data, user_signature, user_cert['subject'])
        if not is_valid:
            print(f"[V{self.node_id}]: Incorrect signature for user!")
            return False
        
        self.original_file_hash = gostcrypto.gosthash.new(
            'streebog256', 
            data=file_data
        ).digest()

        fragments = encode(file_data, self.m, self.n)
        self.fragment = fragments[self.node_id - 1]

        self.all_hashes = {}
        for i, frag in enumerate(fragments):
            h = gostcrypto.gosthash.new('streebog256', data=frag).digest()
            self.all_hashes[i] = h
        
        self.user_signature = user_signature
        return True

    def get_fragment(self):
        return self.fragment
    
    def get_all_hashes(self):
        return self.all_hashes
    
    def sign_confirmation(self, user_id: str, file_hash: bytes):
        """
        File getting confirmation
        """
        data_to_sign = user_id.encode('utf-8') + file_hash
        signature = self.member.sign_data(data_to_sign)
        print(f"[V{self.node_id}] Accept signed!")
        return signature

if __name__ == "__main__":

    from ca.ca import CertificateAuthority
    from ca.member import Member

    print("\nCrating CA...")                                                                                     
    ca = CertificateAuthority(name="Test-CA-Lab3")                                                                    
    print(f"CA created: {ca.name}")                                                                              

    print("\nCreating user (Alice)...")                                                                   
    alice = Member(name="Alice", ca=ca, scheme=Member.SCHEME_GOST)  
    alice.request_certificate()    
    user_cert = alice.certificate                                              
    print(f"Alice created")                                                                                     
    print(f"Alice's public key: {alice.public_key.hex()[:32]}...")    
    
    print(f"Creating nodes:")
    nodes = []                                                                                                        
    for i in range(1, 6):                                                                                             
        node_member = Member(name=f"StorageNode{i}", ca=ca, scheme=Member.SCHEME_GOST) 
        node_member.request_certificate()                               
        node = StorageNode(node_id=i, ca=ca, member=node_member)                                                      
        nodes.append(node)                                                                                            
        print(f"V{i} created")   

    print(f"Creating data...") 
    test_file = b"Secret document: This is a test file for distributed storage!"   
    print(f"Length: {len(test_file)}") 
    print(f"Content: {test_file}")

    print(f"Alice signs...")
    user_signature = alice.sign_data(test_file)
    print(f"Signature ({len(user_signature)} bytes): {user_signature.hex()[:40]}")

    print(f"Sending files to nodes...")
    user_cert = alice.certificate

    for node in nodes:
        success = node.receive_file(
            file_data=test_file,
            user_signature=user_signature,
            user_cert=user_cert
        )
        if success:
            print(f"Node {node.node_id} accepted file!")
        else:
            print(f"Node {node.node_id} denied file!")
        
    print(f"Check for saved data...")
    for node in nodes:
        frag = node.get_fragment()
        hashes = node.get_all_hashes()
        print(f"V{node.node_id}: fragment {len(frag)} bytes, hashes: {len(hashes)}")
    
    print(f"Check for the same hash-values in nodes:")
    reference_hashes = nodes[0].get_all_hashes()
    all_match = True

    for node in nodes[1:]:
        node_hashes = node.get_all_hashes()
        for idx in reference_hashes:
            if reference_hashes[idx] != node_hashes.get(idx):
                print(f"Hash F{idx} doesn't match")
                all_match = False
    
    if all_match:
        print(f"Same hashes between all nodes!")
    else:
        print(f"Different hashes between all nodes!")
    
    print(f"Nodes confirmation")
    for node in nodes:
        confirmation = node.sign_confirmation("Alice", node.original_file_hash)
        print(f"Node{node.node_id} signed confirmation!")
    
    print(f"Test: invalid signature...")
    bad_signature = b"\x00" * len(user_signature)
    test_node = StorageNode(node_id=99, ca=ca, member=Member(name="TestNode", ca=ca, scheme=Member.SCHEME_GOST))

    result = test_node.receive_file(
        file_data=test_file,
        user_signature=bad_signature,
        user_cert=user_cert
    )

    if not result:
        print(f"Node denied file with incorrect signature!")
    else:
        print(f"Error: Node accepted file with incorrect signature!")

