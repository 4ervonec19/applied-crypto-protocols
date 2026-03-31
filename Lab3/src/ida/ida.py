# IDA logic
from .matrix import vandermonde, matrix_multiply, matrix_inverse, matrix_transpose

def encode(data: bytes, m: int, n:int) -> list:
    """
    Splits data on n parts that each m is enough for recovery

    params:
        data (bytes): initial data
        m (int): min parts
        n (int): num parts
    
        returns:
            list fragments (each -- bytes)
    """
    if len(data) == 0:
        raise ValueError("Empty data")
    if m > n:
        raise ValueError("m can't be greate than n")
    
    padding_len = m - (len(data) % m)
    padded_data = data + bytes([padding_len] * padding_len)

    num_cols = len(padded_data) // m
    M = [[0] * num_cols for _ in range(m)]

    for col in range(num_cols):
        for row in range(m):
            M[row][col] = padded_data[col * m + row]
    
    # Vandermonde
    x_values = list(range(1, n + 1))
    A = vandermonde(x_values, m)

    fragments_matrix = matrix_multiply(A, M)

    fragments = []
    for i in range(n):
        fragment_bytes = bytes(fragments_matrix[i])
        fragments.append(fragment_bytes)
    
    return fragments

def decode(fragments: list, m: int, n: int) -> bytes:
    """
    Data decoding from fragments:

    params:
        fragments: list of n elements
    """
    if len(fragments) != n:
        raise ValueError(f"Expected {n} fragments. {len(fragments)} got")
    
    available_indices = [i for i, frag in enumerate(fragments) if frag is not None]
    if len(available_indices) < m:
        raise ValueError(f"Not enough fragments: got {len(available_indices)}, required {m}")

    selected_indices = available_indices[:m]
    selected_fragments = [fragments[i] for i in selected_indices]

    x_values = list(range(1, n + 1))
    A_full = vandermonde(x_values, m)
    A_prime = [A_full[i] for i in selected_indices]

    A_prime_inv = matrix_inverse(A_prime)

    num_cols = len(selected_fragments[0])
    F_prime = [[selected_fragments[j][col] for j in range(m)] for col in range(num_cols)]
    F_prime_T = matrix_transpose(F_prime)

    M_recovered = matrix_multiply(A_prime_inv, F_prime_T)

    data_bytes = []
    for col in range(num_cols):
        for row in range(m):
            data_bytes.append(M_recovered[row][col])
    
    padding_len = data_bytes[-1]
    if padding_len > 0:
        original_data = bytes(data_bytes[:-padding_len])
    else:
        original_data = bytes(data_bytes)
    
    return original_data

if __name__ == "__main__":
    
    original_data = b"Hello, World! This is a test message for IDA."
    m = 3
    n = 5

    print(f"\nOriginal data ({len(original_data)} bytes):")
    print(f"  {original_data}")

    print(f"\nEncoding (m={m}, n={n})...")
    fragments = encode(original_data, m, n)

    for i, frag in enumerate(fragments):
        print(f"  Fragment {i+1}: {len(frag)} byte = {frag.hex()[:20]}...")
    
    print(f"\nDecoding (fragments 2 and 4 lost)...")
    damaged = [fragments[0], None, fragments[2], None, fragments[4]]
    
    recovered = decode(damaged, m, n)
    print(f"  Recovered: {recovered}")

    if recovered == original_data:
        print("\nSuccess!")
    else:
        print("\nFault...")
        print(f"Expected: {original_data}")
        print(f"Got: {recovered}")








