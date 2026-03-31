# Matrix operations
from .gf256 import add, multiply, inverse, divide

def matrix_add(A, B):
    """
    Calc matrix add (A, B)
    """
    k = len(A)
    C = [[0] * k for _ in range(k)]
    for i in range(k):
        for j in range(k):
            C[i][j] ^= add(A[i][j], B[i][j])
    return C

def matrix_multiply(A, B):
    """
    Calc matrix multiplication

    params:
        A: k x m
        B: m x n
    """
    k = len(A)
    m = len(A[0])
    n = len(B[0])

    C = [[0] * n for _ in range(k)]
    for i in range(k):
        for j in range(n):
            for t in range(m):
                C[i][j] ^= multiply(A[i][t], B[t][j])
    
    return C

def matrix_transpose(A):
    """
    Returns transposed matrix (A^T)
    """
    k = len(A)
    m = len(A[0])

    C = [[0] * k for _ in range(m)]
    for i in range(k):
        for j in range(m):
            C[j][i] = A[i][j]

    return C

def vandermonde(x_values: list, m: int) -> list:
    """
    Makes Vandermonde matrix (n x m)
    
    params:
        x_values (list): GF(2^8) elements
        m (int): num cols

    returns:
        matrux (n x m)
    """
    n = len(x_values)
    V = [[0] * m for _ in range(n)]

    for i in range(n):
        x = x_values[i]
        power_of_x = 1

        for j in range(m):
            V[i][j] = power_of_x
            power_of_x = multiply(power_of_x, x)

    return V

def matrix_inverse(A):
    """
    Calc inversed matrix

    params:
        A: input matrix
    """

    n = len(A)
    I = [[1 if i == j else 0 for j in range(n)] for i in range(n)]
    M = [row[:] for row in A]

    for col in range(n):
        pivot_row = None
        for row in range(col, n):
            if M[row][col] != 0:
                pivot_row = row
                break
        
        M[col], M[pivot_row] = M[pivot_row], M[col]
        I[col], I[pivot_row] = I[pivot_row], I[col]

        pivot = M[col][col]
        inv_pivot = inverse(pivot)

        for j in range(n):
            M[col][j] = multiply(M[col][j], inv_pivot)
            I[col][j] = multiply(I[col][j], inv_pivot)
        
        for row in range(n):
            if row != col and M[row][col] != 0:
                factor = M[row][col]
                for j in range(n):
                    M[row][j] ^= multiply(factor, M[col][j])
                    I[row][j] ^= multiply(factor, I[col][j])
    return I

if __name__ == "__main__":

    V = vandermonde([1, 2, 3, 4], 3)
    print(f"V:")
    for row in V:
        print(f"   {[f'0x{x:02X}' for x in row]}")
    
    A = [
        [1, 1, 1],
        [1, 2, 4],
        [1, 3, 9],
    ]
    
    A_inv = matrix_inverse(A)
    
    print(f"A^(-1)")
    for row in A_inv:
        print(f"   {[f'0x{x:02X}' for x in row]}")
    
    print(f"Check A*A^(-1)")
    I = matrix_multiply(A, A_inv)
    for row in I:
        print(f"   {[f'0x{x:02X}' for x in row]}")

    print(f"Valid matrix ops!")