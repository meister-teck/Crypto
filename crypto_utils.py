
def xor_bytes(a, b):
    """XOR entre deux séquences d'octets (ou listes d'entiers) de même longueur."""
    return [x ^ y for x, y in zip(a, b)]

def xor_strings(s1, s2):
    """XOR de deux chaînes caractère par caractère (codes ASCII)."""
    return ''.join(chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(s1, s2))

def pad_to_length(data, length, pad_char='\x00'):
    """Bourrage d'une liste ou chaîne jusqu'à une longueur donnée."""
    if len(data) >= length:
        return data
    return data + [pad_char] * (length - len(data))

def text_to_bytes(text):
    """Convertit une chaîne en liste d'entiers (codes ASCII)."""
    return [ord(c) for c in text]

def bytes_to_text(byte_list):
    """Convertit une liste d'entiers en chaîne."""
    return ''.join(chr(b) for b in byte_list)

def text_to_bits(text):
    """Convertit une chaîne en liste de bits (0/1)."""
    bits = []
    for c in text:
        bits.extend([int(b) for b in format(ord(c), '08b')])
    return bits

def bits_to_text(bits):
    """Convertit une liste de bits en chaîne."""
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) == 8:
            chars.append(chr(int(''.join(str(b) for b in byte), 2)))
    return ''.join(chars)