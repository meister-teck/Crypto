def left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

def padding(message):
    message = bytearray(message, 'utf-8')
    original_length = len(message) * 8

    message.append(0x80)  

    while (len(message) * 8) % 512 != 448:
        message.append(0)

    message += original_length.to_bytes(8, 'big')
    return message

def split_blocks(message):
    return [message[i:i+64] for i in range(0, len(message), 64)]

def generate_W(block):
    W = []

    for i in range(16):
        W.append(int.from_bytes(block[i*4:(i*4)+4], 'big'))

    for i in range(16, 80):
        val = W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16]
        W.append(left_rotate(val, 1))

    return W

def compression(block, H):
    W = generate_W(block)
    A, B, C, D, E = H

    for t in range(80):
        if t < 20:
            f = (B & C) | ((~B) & D)
            K = 0x5A827999
        elif t < 40:
            f = B ^ C ^ D
            K = 0x6ED9EBA1
        elif t < 60:
            f = (B & C) | (B & D) | (C & D)
            K = 0x8F1BBCDC
        else:
            f = B ^ C ^ D
            K = 0xCA62C1D6

        TEMP = (left_rotate(A, 5) + f + E + K + W[t]) & 0xFFFFFFFF
        E = D
        D = C
        C = left_rotate(B, 30)
        B = A
        A = TEMP

    return [
        (H[0] + A) & 0xFFFFFFFF,
        (H[1] + B) & 0xFFFFFFFF,
        (H[2] + C) & 0xFFFFFFFF,
        (H[3] + D) & 0xFFFFFFFF,
        (H[4] + E) & 0xFFFFFFFF
    ]

def sha1(message):

    H = [0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0]
    message = padding(message)
    blocks = split_blocks(message)
    for block in blocks:
        H = compression(block, H)
    return ''.join(f"{h:08x}" for h in H)

# -------------------- SHA256 --------------------
def right_rotate(n, b):
    return ((n >> b) | (n << (32 - b))) & 0xFFFFFFFF

def padding(message):
    message = bytearray(message, 'utf-8')
    original_length = len(message) * 8
    message.append(0x80)
    while (len(message) * 8) % 512 != 448:
        message.append(0)
    message += original_length.to_bytes(8, 'big')
    return message

def split_blocks(message):
    return [message[i:i+64] for i in range(0, len(message), 64)]

def generate_W(block):
    W = []
    for i in range(16):
        W.append(int.from_bytes(block[i*4:(i*4)+4], 'big'))
    for i in range(16, 64):
        s0 = right_rotate(W[i-15], 7) ^ right_rotate(W[i-15], 18) ^ (W[i-15] >> 3)
        s1 = right_rotate(W[i-2], 17) ^ right_rotate(W[i-2], 19) ^ (W[i-2] >> 10)
        W.append((W[i-16] + s0 + W[i-7] + s1) & 0xFFFFFFFF)
    return W

def compression(block, H):
    W = generate_W(block)
    a, b, c, d, e, f, g, h = H
    
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    for t in range(64):
        ch = (e & f) ^ (~e & g)
        maj = (a & b) ^ (a & c) ^ (b & c)
        
        Sigma0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
        Sigma1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
        
        T1 = (h + Sigma1 + ch + K[t] + W[t]) & 0xFFFFFFFF
        T2 = (Sigma0 + maj) & 0xFFFFFFFF
        
        h = g
        g = f
        f = e
        e = (d + T1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (T1 + T2) & 0xFFFFFFFF

    return [
        (H[0] + a) & 0xFFFFFFFF, (H[1] + b) & 0xFFFFFFFF,
        (H[2] + c) & 0xFFFFFFFF, (H[3] + d) & 0xFFFFFFFF,
        (H[4] + e) & 0xFFFFFFFF, (H[5] + f) & 0xFFFFFFFF,
        (H[6] + g) & 0xFFFFFFFF, (H[7] + h) & 0xFFFFFFFF
    ]

def sha256(message):
    H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    
    message = padding(message)
    blocks = split_blocks(message)
    
    for block in blocks:
        H = compression(block, H)
        
    return ''.join(f"{h:08x}" for h in H)




def inverse_modulaire(a, m):
    r0, r1 = a, m
    x0, x1 = 1, 0
    while r1 != 0:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        x0, x1 = x1, x0 - q * x1
    if r0 != 1:
        return None
    return x0 % m


