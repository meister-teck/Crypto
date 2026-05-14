#!/usr/bin/env python3
# main.py - Version sans password_vault

import getpass
import random
from user_manager import load_users, authenticate, create_user, modify_user, delete_user
from symmetric_algorithms import *
from hash_algorithms import sha1, sha256


DES_KEY_BITS = [random.randint(0, 1) for _ in range(64)]
DES_IV_BITS = [random.randint(0, 1) for _ in range(64)]

# ========== Menus ==========
def menu_admin(users, current_user):
    while True:
        print("\n===== MENU ADMINISTRATEUR =====")
        print("1. Créer un utilisateur")
        print("2. Modifier un utilisateur")
        print("3. Supprimer un utilisateur")
        print("4. Lister les utilisateurs")
        print("5. Tester hachage (SHA1, SHA256)")
        print("6. Tester chiffrement symétrique (César, Vigenère, Vernam, RC4, DES, modes)")
        print("7. Tester bibliothèques Python")
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
            new_mdp = getpass.getpass("Nouveau mot de passe (laisser vide) : ")
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
        print("3. Tester bibliothèques Python")
        print("0. Déconnexion")
        choix = input("Votre choix : ")

        if choix == "1":
            test_hashage()
        elif choix == "2":
            test_symetrique()
        elif choix == "3":
            test_bibliotheques()
        elif choix == "0":
            break
        else:
            print("Choix invalide.")

# ========== Fonctions de test ==========
def test_hashage():
    print("\n--- Test des fonctions de hachage maison ---")
    texte = input("Texte à hacher : ")
    print(f"SHA1 maison   : {sha1(texte)}")
    print(f"SHA256 maison : {sha256(texte)}")
    # Comparaison avec hashlib
    import hashlib
    print(f"SHA1 hashlib   : {hashlib.sha1(texte.encode()).hexdigest()}")
    print(f"SHA256 hashlib : {hashlib.sha256(texte.encode()).hexdigest()}")

def test_symetrique():
    print("\n--- Test des algorithmes symétriques ---")
    print("1. César")
    print("2. Vigenère")
    print("3. Vernam (XOR)")
    print("4. RC4")
    print("5. DES simplifié (bloc 64 bits) + modes CFB/CBC/OFB")
    choix = input("Choisissez un algorithme : ")

    if choix == "1":
        texte = input("Texte à chiffrer : ")
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
        cle_auto = input("Clé (laisser vide pour génération aléatoire) : ")
        if cle_auto:
            cle, chiffre = chiffrervernam(texte, cle_auto)
        else:
            cle, chiffre = chiffrervernam(texte)
        print(f"Clé générée : {cle}")
        print(f"Chiffré (repr) : {repr(chiffre)}")
        clair = dechiffrer_vernam(chiffre, cle)
        print(f"Déchiffré : {clair}")
    elif choix == "4":
        texte = input("Texte : ")
        cle = input("Clé RC4 : ")
        chiffre = rc4_crypt(cle, texte)
        print(f"Chiffré (repr) : {repr(chiffre)}")
        clair = rc4_crypt(cle, chiffre)
        print(f"Déchiffré : {clair}")
    elif choix == "5":
        texte = input("Texte (max 8 caractères pour bloc unique) : ")
        bits = string_to_bitlist(texte)
        if len(bits) < 64:
            bits += [0] * (64 - len(bits))
        elif len(bits) > 64:
            print("Texte trop long, on prend les 64 premiers bits.")
            bits = bits[:64]
        chiffre_bits = des_encrypt_block(bits, DES_KEY_BITS)
        print("Bloc chiffré (début) :", chiffre_bits[:32], "...")
        print("\n--- Test des modes (CFB, CBC, OFB) sur une chaîne ---")
        msg = input("Message à chiffrer avec mode : ")
        iv = [random.randint(0, 1) for _ in range(64)]
        print("Mode CFB :")
        cfb = mode_cfb(msg, iv, DES_KEY_BITS, des_encrypt_block)
        print(f"Chiffré CFB : {repr(cfb)}")
        # Note : déchiffrement des modes non implémenté ici
        print("(Le déchiffrement des modes n'est pas implémenté dans cette démo)")

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
        print("✗ cryptography non installée (pip install cryptography)")
    try:
        import bcrypt
        print("✓ bcrypt installée")
    except ImportError:
        print("✗ bcrypt non installée (pip install bcrypt)")
    try:
        import hashlib
        print("✓ hashlib (bibliothèque standard)")
    except:
        pass

# ========== Programme principal ==========
def main():
    users = load_users()
    print("=== Système de gestion de mots de passe (version simplifiée) ===")
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

if __name__ == "__main__":
    main()