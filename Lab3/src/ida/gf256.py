# GF(2^8) Math tools

def add(a: int, b: int) -> int:
    return a ^ b

def multiply(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit:
            a ^= 0x1B
        b >>= 1
    return p

def inverse(a: int) -> int:
    if a == 0:
        raise ValueError("Nil has no inverse!")
    for x in range(1, 256):
        if multiply(a, x) == 1:
            return x
    raise ValueError(f"Inverse not found for {a}")

def divide(a: int, b: int) -> int:
    if b == 0:
        raise ValueError("Zero division!")
    return multiply(a, inverse(b))

if __name__ == "__main__":

    # multiply:
    a = 0x57
    b = 0x83
    assert multiply(a, b) == 0xC1

    # add
    a = 0xD4
    b = 0x83
    assert add(a, b) == 0x57

    # inverse
    a = 0x57
    b = 0x57
    assert multiply(inverse(a), b) == 0x01

    print(f"GF(2^8) math works fine!")


    