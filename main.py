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
        print("5. Tester hachage (SHA1, SHA256)")
        print("6. Tester chiffrement symétrique (César, Vigenère, Vernam, RC4, DES)")
        print("7. Tester algorithmes asymétriques (RSA, ECC , elGamal)")
        print("8. Tester bibliothèques Python")
        print("0. Retour")
        choix = input("Votre choix : ")

        if choix == "1":
            nom = input("Nom : ")
            mdp = getpass.getpass("Mot de passe : ")
            role = input("Rôle (admin/user) : ").lower()
            if role not in ("admin", "user"):
                role = "user"
            create_user(users, nom, mdp, role)
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
        elif choix == "0":
            break
        else:
            print("Choix invalide.")

def menu_user(username):
    while True:
        print("\n===== MENU UTILISATEUR =====")
        print("1. Tester hachage (SHA1, SHA256)")
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
    print(f"SHA1    : {sha1(texte)}")
    print(f"SHA256  : {sha256(texte)}")
    import hashlib
    print(f"SHA1 hashlib   : {hashlib.sha1(texte.encode()).hexdigest()}")
    print(f"SHA256 hashlib : {hashlib.sha256(texte.encode()).hexdigest()}")

def test_symetrique():
    print("\n--- Test des algorithmes symétriques ---")
    print("1. César")
    print("2. Vigenère")
    print("3. Vernam (XOR)")
    print("4. RC4")
    print("5. DES (bloc 64 bits, clé 64 bits)")
    choix = input("Choisissez un algorithme : ")

    if choix == "1":
        texte = input("Texte : ")
        dec = int(input("Décalage : "))
        chiffre = chiffrerCesar(texte, dec)
        print(f"Chiffré : {chiffre}")
        clair = dechiffrerCesar(chiffre, dec)
        print(f"Déchiffré : {clair}")
    elif choix == "2":
        texte = input("Texte : ")
        cle = input("Clé : ")
        chiffre = chiffrerVigenere(texte, cle)
        print(f"Chiffré : {chiffre}")
        clair = dechiffrerVigenere(chiffre, cle)
        print(f"Déchiffré : {clair}")
    elif choix == "3":
        texte = input("Texte : ")
        cle_auto = input("Clé (laisser vide pour auto) : ")
        if cle_auto:
            key, chiffre = chiffrerVernam(texte, cle_auto)
        else:
            key, chiffre = chiffrerVernam(texte)
        print(f"Clé : {key}")
        print(f"Chiffré : {repr(chiffre)}")
        clair = DechiffrerVernam(chiffre, key)
        print(f"Déchiffré : {clair}")
    elif choix == "4":
        texte = input("Texte : ")
        cle = input("Clé RC4 : ")
        chiffre = RC4(cle, texte)
        print(f"Chiffré : {repr(chiffre)}")
        clair = RC4(cle, chiffre)
        print(f"Déchiffré : {clair}")
    elif choix == "5":

        texte = input("Texte (max 8 caractères) : ")
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
 
        print("(Le déchiffrement DES n'est pas implémenté ici)")
    else:
        print("Choix invalide.")

def test_bibliotheques():
    print("\n--- Test des bibliothèques Python ---")
    try:
        import cryptography
        print("✓ cryptography installée")
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
        f = Fernet(key)
        token = f.encrypt(b"test")
        print(f"  Exemple Fernet : {token}")
    except ImportError:
        print("cryptography non installée (pip install cryptography)")
    try:
        import bcrypt
        print("bcrypt installée")
    except ImportError:
        print("bcrypt non installée (pip install bcrypt)")
    try:
        import hashlib
        print("hashlib")
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
                menu_user(username)
        else:
            print("Échec de l'authentification. Réessayez.")
def test_asymetrique():
    print("\n--- Test des algorithmes asymétriques ---")
    print("1. RSA")
    print("2. EC El GAMAL")
    print("3. ElGamal")
    choix = input("Choisissez un algorithme : ")

    if choix == "1":
        public_key, private_key = generate_key()
        print(f"Clé publique : {public_key}")
        print(f"Clé privée : {private_key}")
        m = int(input("Message à chiffrer (entier) : "))
        c = encrypt(public_key, m)
        print(f"Chiffré : {c}")
        m_dechiffre = decrypt(private_key, c)
        print(f"Déchiffré : {m_dechiffre}")
    elif choix == "2":
        m = int(input("Message à chiffrer (entier) : "))
        p, G = deux_nombres_premiers()
        P, k = cle_publique(p, G)
        print(f"Clé publique : P={P}, G={G}")
        c1, c2 = ecelgamal_chiffrement(m)
        print(f"Chiffré : c1={c1}, c2={c2}")
        m_dechiffre = ecelgamal_dechiffrement(k, c1, c2)
        print(f"Déchiffré : {m_dechiffre}")
    elif choix == "3":
        m = int(input("Message à chiffrer (entier) : "))
        p, g, c1, c2 = elgamal_chiffrement(m)
        print(f"Chiffré : (p={p}, g={g}, c1={c1}, c2={c2})")
        m_dechiffre = elgamal_dechiffrement(p, g, c1, c2)
        print(f"Déchiffré : {m_dechiffre}")
    else:
        print("Choix invalide.")
if __name__ == "__main__":
    main()
