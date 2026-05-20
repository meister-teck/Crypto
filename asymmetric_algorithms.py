import random

def inversement(a,n):
    return pow(a,1,n)

def est_premier(n):
    if n < 2:
        return False
    
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    
    return True

def deux_nombres_premiers():
    premiers = []

    while len(premiers) < 2:
        x = random.randint(256, 1000)

        if est_premier(x):
            premiers.append(x)

    return premiers[0], premiers[1]

#--------------El GAMAL-------------------------
import random
def generate_keys(p, g):
    x = random.randint(1, p - 2)
    h = pow(g, x, p)
    return (p, g, h), x
    
def elgamal_encrypt(public_key, m):
    p, g, h = public_key
    k = random.randint(1, p-2)
    
    c1 = pow(g, k, p)
    s = pow(h, k, p)
    c2 = (m * s) % p
    
    return c1, c2

def elgamal_decrypt(private_key, public_key, c1, c2):
    p, g, h = public_key
    x = private_key
    
    s = pow(c1, x, p)
    # pow(s, -1, p) calcule l'inverse modulaire (nécessite Python 3.8+)
    s_inv = pow(s, -1, p)
    m = (c2 * s_inv) % p
    
    return m

# ------ RSA-----
from math import gcd
def generate_key():
    p, q = deux_nombres_premiers()
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randint(2, phi - 1)
    while gcd(e, phi) != 1:
        e += 1
    d = pow(e, -1, phi)
    return (e, n), (d, n)

def encrypt(public_key, m):
    e, n = public_key
    return pow(m, e, n)

def decrypt(private_key, cipher):
    d, n = private_key
    return pow(cipher, d, n)

#--------------EC El GAMAL-------------------------
def cle_publique(p, G):
    k = random.randint(1, p-2)
    P = k * G
    return P , k

    
def ecelgamal_chiffrement(m, p, G, P):
    r = random.randint(1, p-2)
    c1 = r * G
    c2 = m + r * P
    return c1, c2 


def ecelgamal_dechiffrement(k, c1, c2):
    M = c2 - k*c1
    return M

def deffie():
    p = 23
    g = 5
 
    a = random.randint(1, p-2)
    b = random.randint(1, p-2)

    A = pow(g, a, p)
    B = pow(g, b, p)

    cle_alice = pow(B, a, p)
    cle_bob = pow(A, b, p)

    if cle_alice == cle_bob:
        print("Clé secrète commune établie !")
        print(cle_alice)

