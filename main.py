#!/usr/bin/env python3
import getpass
import random
from user_manager import *
from symmetric_algorithms import *
from hash_algorithms import *
from asymmetric_algorithms import *

def menu_admin(users, current_user):
    while True:
        print("\n===== MENU ADMINISTRATEUR =====")
        print("1. Créer un utilisateur")
        print("2. Modifier un utilisateur")
        print("3. Supprimer un utilisateur")
        print("4. Lister les utilisateurs")
        print("5. Tester hachage ")
        print("6. Tester chiffrement symétrique ")
        print("7. Tester algorithmes asymétriques ")
        print("8. Tester bibliothèques Python")
        print("9. Modifier mon mot de passe")
        print("0. Retour")
        choix = input("Votre choix : ")

        if choix == "1":
            nom = input("Nom : ")
            mdp = getpass.getpass("Mot de passe : ")
            role = input("Rôle (admin/user) : ").lower()
            if role not in ("admin", "user"):
                role = "user"
            
            method = "hash"
            key = None
            
            HASH_ALGOS = ["sha256", "sha1"]
            print("Algorithme de hachage pour le mot de passe :")
            for i, h_name in enumerate(HASH_ALGOS, 1):
                print(f"{i}. {h_name.upper()}")
            alg_choix = input(f"Choix (1-{len(HASH_ALGOS)}) : ")
            try:
                idx = int(alg_choix) - 1
                if 0 <= idx < len(HASH_ALGOS):
                    algo = HASH_ALGOS[idx]
                else:
                    algo = HASH_ALGOS[0]
            except ValueError:
                algo = HASH_ALGOS[0]
                    
            create_user(users, nom, mdp, role, method, algo, key)
        elif choix == "2":
            nom = input("Nom à modifier : ")
            new_mdp = getpass.getpass("Nouveau mdp (laisser vide) : ")
            new_role = input("Nouveau rôle (admin/user, laisser vide) : ").lower()
            modify_user(users, nom, new_mdp if new_mdp else None,
                        new_role if new_role in ("admin", "user", "") else None)
        elif choix == "3":
            nom = input("Nom à supprimer : ")
            delete_user(users, nom, current_user["username"])
        elif choix == "4":
            print("\nUtilisateurs :")
            for u, infos in users.items():
                print(f" - {u} (rôle: {infos['role']})")
        elif choix == "5":
            test_hashage()
        elif choix == "6":
            test_symetrique()
        elif choix == "7":
            test_asymetrique()
        elif choix == "8":
            test_bibliotheques()
        elif choix == "9":
            new_mdp = getpass.getpass("Nouveau mot de passe : ")
            modify_user(users, current_user["username"], new_mdp, None)
        elif choix == "0":
            break
        else:
            print("Choix invalide.")

def menu_user(users, username):
    while True:
        print("\n===== MENU UTILISATEUR =====")
        print("1. Tester hachage ")
        print("2. Tester chiffrement symétrique")
        print("3. Tester algorithmes asymétriques")
        print("4. Tester bibliothèques Python")
        print("0. Déconnexion")
        choix = input("Votre choix : ")

        if choix == "1":
            test_hashage()
        elif choix == "2":
            test_symetrique()
        elif choix == "3":
            test_asymetrique()
        elif choix == "4":
            test_bibliotheques()
        elif choix == "0":
            break
        else:
            print("Choix invalide.")

def test_hashage():
    print("\n--- Test des fonctions de hachage  ---")
    texte = input("Texte à hacher : ")
    print("1. SHA1")
    print("2. SHA256")
    choix = input("Choisissez un algorithme : ")
    
    import hashlib
    if choix == "1":
        print(f"SHA1 (Implémentation) : {sha1(texte)}")
        print(f"SHA1 (hashlib)        : {hashlib.sha1(texte.encode()).hexdigest()}")
    elif choix == "2":
        print(f"SHA256 (Implémentation) : {sha256(texte)}")
        print(f"SHA256 (hashlib)        : {hashlib.sha256(texte.encode()).hexdigest()}")
    else:
        print("Choix invalide.")

def run_cesar():
    texte = input("Mot de passe : ")
    dec = int(input("Décalage : "))
    chiffre = chiffrerCesar(texte, dec)
    print(f"Chiffré : {chiffre}")
    clair = dechiffrerCesar(chiffre, dec)
    print(f"Déchiffré : {clair}")

def run_vigenere():
    texte = input("Mot de passe : ")
    cle = input("Clé : ")
    chiffre = chiffrerVigenere(texte, cle)
    print(f"Chiffré : {chiffre}")
    clair = dechiffrerVigenere(chiffre, cle)
    print(f"Déchiffré : {clair}")

def run_vernam():
    texte = input("Mot de passe : ")
    cle_auto = input("Clé (laisser vide pour auto) : ")
    if cle_auto:
        key = cle_auto
        chiffre = xor_encrypt(texte, key)
    else:
        key, chiffre = chiffrerVernam(texte)
    print(f"Clé : {key}")
    print(f"Chiffré : {repr(chiffre)}")
    clair = DechiffrerVernam(chiffre, key)
    print(f"Déchiffré : {clair}")

def run_rc4():
    texte = input("Mot de passe : ")
    cle = input("Clé RC4 : ")
    chiffre = RC4(texte, cle)
    print(f"Chiffré : {repr(chiffre)}")
    clair = RC4(chiffre, cle)
    print(f"Déchiffré : {clair}")

def run_des():
    texte = input("Mot de passe (max 8 caractères) : ")
    if len(texte) > 8:
        print("Tronqué à 8 caractères")
        texte = texte[:8]

    bits = []
    for c in texte:
        bits.extend([int(b) for b in format(ord(c), '08b')])

    if len(bits) < 64:
        bits += [0] * (64 - len(bits))

    key_bits = [random.randint(0,1) for _ in range(64)]
    print("Clé (bits) :", key_bits[:16], "...")
    chiffre_bits = DES(bits, key_bits)
    print("Chiffré (bits, premiers 32) :", chiffre_bits[:32], "...")

    clair_bits = DES(chiffre_bits, key_bits)
    chars = []
    for i in range(0, len(clair_bits), 8):
        byte = clair_bits[i:i+8]
        if len(byte) == 8:
            chars.append(chr(int(''.join(str(b) for b in byte), 2)))
    print(f"Déchiffré : {''.join(chars).rstrip(chr(0))}")

SYM_ALGOS = {
    "César": run_cesar,
    "Vigenère": run_vigenere,
    "Vernam (XOR)": run_vernam,
    "RC4": run_rc4,
    "DES (bloc 64 bits, clé 64 bits)": run_des
}

def test_symetrique():
    print("\n--- Test des algorithmes symétriques ---")
    noms = list(SYM_ALGOS.keys())
    for i, name in enumerate(noms, 1):
        print(f"{i}. {name}")
    choix = input("Choisissez un algorithme : ")
    
    try:
        idx = int(choix) - 1
        if 0 <= idx < len(noms):
            SYM_ALGOS[noms[idx]]()
        else:
            print("Choix invalide.")
    except ValueError:
        print("Choix invalide.")

def test_bibliotheques():
    print("\n--- Test des bibliothèques Python ---")
    try:
        import cryptography
        print("✓ cryptography installée")
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
        f = Fernet(key)
        token = f.encrypt(b"test_mot_de_passe")
        print(f"  Exemple Fernet (chiffré) : {token}")
        print(f"  Exemple Fernet (déchiffré) : {f.decrypt(token).decode()}")
    except ImportError:
        print("cryptography non installée (pip install cryptography)")
    try:
        import bcrypt
        print("✓ bcrypt installée")
        mot_de_passe = b"mot_de_passe_secret"
        hashed = bcrypt.hashpw(mot_de_passe, bcrypt.gensalt())
        print(f"  Hash bcrypt : {hashed}")
        print(f"  Vérification : {bcrypt.checkpw(mot_de_passe, hashed)}")
    except ImportError:
        print("bcrypt non installée (pip install bcrypt)")
    try:
        import hashlib
        print("✓ hashlib installée")
        print(f"  SHA256 hashlib : {hashlib.sha256(b'test').hexdigest()}")
    except:
        pass

def main():
    users = load_users()
    print("=== Système de gestion de mots de passe (crypto) ===")
    while True:
        print("\n--- Connexion ---")
        username = input("Nom d'utilisateur : ")
        password = getpass.getpass("Mot de passe : ")
        user = authenticate(users, username, password)
        if user:
            print(f"Bienvenue {username} (rôle: {user['role']})")
            if user["role"] == "admin":
                menu_admin(users, user)
            else:
                menu_user(users, username)
        else:
            print("Échec de l'authentification. Réessayez.")
def run_rsa():
    public_key, private_key = generate_key()
    print(f"Clé publique : {public_key}")
    print(f"Clé privée : {private_key}")
    texte = input("Message à chiffrer : ")
    bytes_msg = texte.encode('utf-8')
    c_list = [encrypt(public_key, b) for b in bytes_msg]
    print(f"Chiffré : {c_list}")
    m_dechiffre = bytes([decrypt(private_key, c) for c in c_list]).decode('utf-8')
    print(f"Déchiffré : {m_dechiffre}")

def run_ec_elgamal():
    texte = input("Message à chiffrer : ")
    p, G = deux_nombres_premiers()
    P, k = cle_publique(p, G)
    print(f"Clé publique : P={P}, G={G}")
    bytes_msg = texte.encode('utf-8')
    c_list = [ecelgamal_chiffrement(b, p, G, P) for b in bytes_msg]
    print(f"Chiffré : {c_list}")
    m_dechiffre = bytes([ecelgamal_dechiffrement(k, c1, c2) for c1, c2 in c_list]).decode('utf-8')
    print(f"Déchiffré : {m_dechiffre}")

def run_elgamal():
    p = int(input("Premier p (p > 255, i.e 767) : "))
    g = int(input("Générateur g : "))
    public_key, private_key = generate_keys(p, g)

    print("Clé publique:", public_key)
    print("Clé privée:", private_key)

    texte = input("Message : ")
    bytes_msg = texte.encode('utf-8')
    c_list = [elgamal_encrypt(public_key, b) for b in bytes_msg]
    print("Chiffré:", c_list)
    m_dechiffre = bytes([elgamal_decrypt(private_key, public_key, c1, c2) for c1, c2 in c_list]).decode('utf-8')
    print("Déchiffré:", m_dechiffre)

ASYM_ALGOS = {
    "RSA": run_rsa,
    "EC El GAMAL": run_ec_elgamal,
    "ElGamal": run_elgamal
}

def test_asymetrique():
    print("\n--- Test des algorithmes asymétriques ---")
    noms = list(ASYM_ALGOS.keys())
    for i, name in enumerate(noms, 1):
        print(f"{i}. {name}")
    choix = input("Choisissez un algorithme : ")

    try:
        idx = int(choix) - 1
        if 0 <= idx < len(noms):
            ASYM_ALGOS[noms[idx]]()
        else:
            print("Choix invalide.")
    except ValueError:
        print("Choix invalide.")
if __name__ == "__main__":
    main()
