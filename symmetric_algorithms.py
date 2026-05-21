from crypto_utils import *
import random
import string


#----------- Fonctions utils ----------
def bourrage(message, taille):
    if len(message) < taille:
        message = message + [0] * (taille - len(message))
    return message

# ---------- César ----------
def chiffrerCesar(texte, n):
    resultat = ""
    
    for char in texte:
        if char.isalpha():
            if char.isupper() :
                base = ord('A') 
            else :
                base = ord('a')
            
            nouveau_char = chr((ord(char) - base + n) % 26 + base)
            resultat += nouveau_char
        else:
            resultat += char
            
    return resultat

def dechiffrerCesar(texte, n):
    return chiffrerCesar(texte, -n)

# ---------- Vigenere ----------
def chiffrerVigenere(texte, cle):
    resultat = ""
    j = 0  

    for i in range(len(texte)):
        char = texte[i]
        if char.isalpha(): 
            decalage = ord(cle[j % len(cle)].upper()) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            new = chr((ord(char) - base + decalage) % 26 + base)
            resultat += new
            j += 1 
        else:
            resultat += char 

    return resultat

def dechiffrerVigenere(texte, cle):
    resultat = ""
    j = 0 

    for i in range(len(texte)):
        char = texte[i]
        if char.isalpha():  
            decalage = ord(cle[j % len(cle)].upper()) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            new = chr((ord(char) - base - decalage) % 26 + base)
            resultat += new
            j += 1  
        else:
            resultat += char  

    return resultat

# ---------- Vernam (XOR)  ----------
def xor_encrypt(text, key):
    if len(text) != len(key) :
        raise ValueError("text and key need to be the same length")
    result = ""
    for i in range(len(text)):
        ascii_text = ord(text[i])
        ascii_key = ord(key[i])
        ascii_result = ascii_key ^ ascii_text
        result += chr(ascii_result)
    return result

def generate_random_string(length):
    caracteres = string.ascii_letters + string.digits
    liste_random = random.choices(caracteres, k=length)
    random_string = ''.join(liste_random)
    return random_string

def chiffrerVernam(text):
    n = len(text)
    key = generate_random_string(n)
    cryptage = xor_encrypt(text, key)
    return key, cryptage

def DechiffrerVernam(cryptage, key):
    return xor_encrypt(cryptage, key)

# ---------- RC4 ----------
def KSA(key_byte):
    S = [i for i in range(256)]
    T = []
    n = len(key_byte)
    for i in range(256):
        T.append(key_byte[i % n])
    j = 0
    for i in range(256):
        j = (j + S[i] + T[i]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def PRGA(S, textlength):
    i = 0
    j = 0
    key = []
    for _ in range(textlength):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = (S[i] + S[j]) % 256
        key.append(K)
    return key

def RC4(text, key):
    key = text_to_bytes(key)
    text = text_to_bytes(text)
    S = KSA(key)
    key_stream = PRGA(S, len(text))
    result = xor_bytes(text, key_stream)
    return bytes_to_text(result)

# ---------- DES ----------
PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

IP_INV = [40, 8, 48, 16, 56, 24, 64, 32,
          39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30,
          37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28,
          35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26,
          33, 1, 41, 9, 49, 17, 57, 25]

E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

P = [16, 7, 20, 21,
     29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2, 8, 24, 14,
     32, 27, 3, 9,
     19, 13, 30, 6,
     22, 11, 4, 25]

S_BOX = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
		[0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
		[4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
		[15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

		[[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
		[3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
		[0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
		[13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

		[[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
		[13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
		[13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
		[1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

		[[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
		[13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
		[10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
		[3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

		[[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
		[14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
		[4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
		[11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

		[[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
		[10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
		[9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
		[4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

		[[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
		[13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
		[1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
		[6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

		[[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
		[1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
		[7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
		[2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

def permute(bits, table):
    return [bits[i - 1] for i in table]

def split(bits):
    return bits[:len(bits)//2], bits[len(bits)//2:]

def generate_keys(key):
    keys = []
    key_56 = permute(key, PC1)
    
    C, D = split(key_56)
    
    for i in range(16):
        shift = SHIFTS[i]
        
        C = C[shift:] + C[:shift]
        D = D[shift:] + D[:shift]
        
        combined = C + D
        round_key = permute(combined, PC2)
        keys.append(round_key)
        
    return keys

def sbox_substitution(bits):
    output = []
    chunks = [bits[i:i+6] for i in range(0, len(bits), 6)]
    for i,c in enumerate(chunks):
        row = (c[0] << 1) + c[5]
        col = (c[1] << 3) + (c[2] << 2) + (c[3] << 1) + c[4]
        val = S_BOX[i][row][col]
        output += [int(x) for x in format(val, "04b")]
    return output

def f_function(r, key):
    expanded = permute(r, E)
    xored = xor_bytes(expanded, key)
    sboxed = sbox_substitution(xored)
    return permute(sboxed, P)

def feistel(l, r, key):
    return r, xor_bytes(l, f_function(r, key))

def DES(block, key):
    keys = generate_keys(key)
    block = permute(block, IP)
    L, R = split(block)
    for i in range(16):
        L, R = feistel(L, R, keys[i])
    return permute(R + L, IP_INV)

def des_process(password, key):
    kb = []
    for c in str(key)[:8].ljust(8, ' '): 
        kb.extend([int(b) for b in format(ord(c), '08b')])
    
    if not password:
        password = " "
    chunks = [password[i:i+8] for i in range(0, len(password), 8)]
    
    final_result = ""
    
    for chunk in chunks:
        # On complète le bloc avec des espaces s'il fait moins de 8 caractères (Padding)
        padded_chunk = chunk.ljust(8, ' ')
        
        # Conversion du bloc en bits
        bits = []
        for c in padded_chunk: 
            bits.extend([int(b) for b in format(ord(c), '08b')])
        
        result_bits = DES(bits, kb)
        
        # Conversion des bits chiffrés en caractères
        chars = []
        for i in range(0, len(result_bits), 8):
            byte = result_bits[i:i+8]
            if len(byte) == 8: 
                chars.append(chr(int(''.join(str(b) for b in byte), 2)))
                
        final_result += ''.join(chars)
        
    return final_result

def DES_decrypt(block, key):
    keys = generate_keys(key)
    keys.reverse() # On inverse les clés pour le déchiffrement
    block = permute(block, IP)
    L, R = split(block)
    for i in range(16):
        L, R = feistel(L, R, keys[i])
    return permute(R + L, IP_INV)

def des_decrypt_process(ciphertext, key):
    kb = []
    for c in str(key)[:8].ljust(8, ' '): 
        kb.extend([int(b) for b in format(ord(c), '08b')])
    
    chunks = [ciphertext[i:i+8] for i in range(0, len(ciphertext), 8)]
    final_result = ""
    
    for chunk in chunks:
        padded_chunk = chunk.ljust(8, ' ')
        bits = []
        for c in padded_chunk: 
            bits.extend([int(b) for b in format(ord(c), '08b')])
        
        result_bits = DES_decrypt(bits, kb) # Appel à DES_decrypt
        
        chars = []
        for i in range(0, len(result_bits), 8):
            byte = result_bits[i:i+8]
            if len(byte) == 8: 
                chars.append(chr(int(''.join(str(b) for b in byte), 2)))
                
        final_result += ''.join(chars)
        
    return final_result


# ---------- Modes de chiffrement par bloc (CFB, CBC, OFB) ----------
def CFB(text, v, key, func, bit_block):
    vecteur = v
    text = text_to_bytes(text)
    text = [text[i:i+bit_block] for i in range(0, len(text), bit_block)]
    key = text_to_bytes(key)
    cipher = b""
    for block in text:
        chiffre_block = func(vecteur, key)
        cipher_block = xor_bytes(block, chiffre_block[:len(block)])
        cipher += cipher_block
        vecteur = cipher_block  
    return bytes_to_text(cipher)

def CBC(text, v, key, func, bit_block):
    vecteur = v
    text = text_to_bytes(text)
    text = [text[i:i+bit_block] for i in range(0, len(text), bit_block)]
    key = text_to_bytes(key)
    cipher = b""
    for block in text:
        xored = xor_bytes(block, vecteur)
        chiffre_block = func(xored, key)
        cipher += chiffre_block
        vecteur = chiffre_block
    return bytes_to_text(cipher)

def OFB(text, v, key, func, bit_block):
    vecteur = v
    text = text_to_bytes(text)
    text = [text[i:i+bit_block] for i in range(0, len(text), bit_block)]
    key = text_to_bytes(key)
    cipher = b""
    for block in text:
        chiffre_block = func(vecteur, key)
        cipher_block = xor_bytes(block, chiffre_block[:len(block)])
        cipher += cipher_block
        vecteur = chiffre_block
    return bytes_to_text(cipher)
