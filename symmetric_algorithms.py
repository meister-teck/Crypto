#----------- Fonctions utils ----------
def bourrage(message, taille):
    if len(message) < taille:
        message = message + [0] * (taille - len(message))
    return message

def xor(bits1, bits2):
    resultat = []
    
    for i in range(len(bits1)):
        if bits1[i] != bits2[i]:
            resultat.append(1)
        else:
            resultat.append(0)
    
    return resultat

def text_to_bytes(text):
    return [ord(c) for c in text]

def bytes_to_text(msg):
    return ''.join(chr(i) for i in msg)

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
            new = chr((ord(char.upper()) - ord('A') + decalage) % 26 + ord('A'))
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
            new = chr((ord(char.upper()) - ord('A') - decalage) % 26 + ord('A'))
            resultat += new
            j += 1  
        else:
            resultat += char  

    return resultat

# ---------- Vernam (XOR)  ----------
import random
import string

def xor_encrypt(text, key):
    result = ''
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
    n = len(cryptage)
    if n != len(key) :
        if n % len(key) == 0:
            key = key * ( n // len(key) )
        else:
            return "La clé doit avoir la même longueur que le texte, ou bien la longueur du texte doit être un multiple de celle de la clé."
    original = xor_encrypt(cryptage, key) 
    return original

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

def RC4(key, text):
    key = text_to_bytes(key)
    text = text_to_bytes(text)
    S = KSA(key)
    key_stream = PRGA(S, len(text))
    result = xor(text, key_stream)
    return bytes_to_text(result)

# ---------- DES simplifié ----------
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

S_BOX = [[[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
     [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
     [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
     [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]]]

def permute(bits, table):
    return [bits[i - 1] for i in table]

def split(bits):
    return bits[:len(bits)//2], bits[len(bits)//2:]

def generate_keys(key):
    return [key for _ in range(16)]

def sbox_substitution(bits):
    output = []
    chunks = [bits[i:i+6] for i in range(0, len(bits), 6)]
    for c in chunks:
        row = (c[0] << 1) + c[5]
        col = (c[1] << 3) + (c[2] << 2) + (c[3] << 1) + c[4]
        val = S_BOX[0][row][col]
        output += [int(x) for x in format(val, "04b")]
    return output

def f_function(r, key):
    expanded = permute(r, E)
    xored = xor(expanded, key)
    sboxed = sbox_substitution(xored)
    return permute(sboxed, P)

def feistel(l, r, key):
    return r, xor(l, f_function(r, key))

def DES(block, key):
    keys = generate_keys(key)
    block = permute(block, IP)
    L, R = split(block)
    for i in range(16):
        L, R = feistel(L, R, keys[i])
    return permute(R + L, IP_INV)

# ---------- Modes de chiffrement par bloc (CFB, CBC, OFB) ----------
def CFB(text, v, key, func, bit_block):
    vecteur = v
    text = text_to_bytes(text)
    text = [text[i:i+bit_block] for i in range(0, len(text), bit_block)]
    key = text_to_bytes(key)
    cipher = b""
    for block in text:
        chiffre_block = func(vecteur, key)
        cipher_block = xor(block, chiffre_block[:len(block)])
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
        xored = xor(block, vecteur)
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
        cipher_block = xor(block, chiffre_block[:len(block)])
        cipher += cipher_block
        vecteur = chiffre_block
    return bytes_to_text(cipher)