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
        print("0. Retour")
        choix = input("Votre choix : ")

        if choix == "1":
            while True:
                nom = input("Nom d'utilisateur : ")
                mdp = getpass.getpass("Mot de passe : ")
                mdp_confirm = getpass.getpass("Confirmer le mot de passe : ")
        
                if mdp == mdp_confirm:
                    break 
                else:
                    print("Erreur : Les mots de passe ne correspondent pas. Veuillez réessayer.\n")
            
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
            while True:
                new_mdp = getpass.getpass("Nouveau mdp (laissez vide pour ne pas modifier) : ")
        
                # Si l'utilisateur laisse vide, pas besoin de confirmation, on sort de la boucle
                if not new_mdp:
                    break
            
                new_mdp_confirm = getpass.getpass("Confirmer le nouveau mot de passe : ")
        
                if new_mdp == new_mdp_confirm:
                    break 
                else:
                    print("Erreur : Les mots de passe ne correspondent pas. Veuillez réessayer.\n")
            
            new_role = input("Nouveau rôle (admin/user, laissez vide pour ne pas modifier) : ").lower()
    
            modify_user(users, nom, new_mdp if new_mdp else None,
                new_role if new_role in ("admin", "user") else None)
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
    import hashlib 
    while True:
        print("\n--- Test des fonctions de hachage  ---")
        print("1. SHA1")
        print("2. SHA256")
        print("0. Retour")
        
        choix = input("Choisissez un algorithme : ")
        
        if choix == "0":
            break
            
        if choix in ("1", "2"):
            texte = input("Texte à hacher : ") 
            
            if choix == "1":
                print(f"SHA1 (Implémentation) : {sha1(texte)}")
                print(f"SHA1 (hashlib)        : {hashlib.sha1(texte.encode()).hexdigest()}")
            elif choix == "2":
                print(f"SHA256 (Implémentation) : {sha256(texte)}")
                print(f"SHA256 (hashlib)        : {hashlib.sha256(texte.encode()).hexdigest()}")
        else:
            print("Choix invalide.")

def run_cesar():
    texte = input("text a chiffrer : ")
    dec = int(input("Décalage : "))
    chiffre = chiffrerCesar(texte, dec)
    print(f"Chiffré : {chiffre}")
    clair = dechiffrerCesar(chiffre, dec)
    print(f"Déchiffré : {clair}")

def run_vigenere():
    texte = input("text a chiffrer : ")
    cle = input("Clé : ")
    chiffre = chiffrerVigenere(texte, cle)
    print(f"Chiffré : {chiffre}")
    clair = dechiffrerVigenere(chiffre, cle)
    print(f"Déchiffré : {clair}")

def run_vernam():
    texte = input("text a chiffrer : ")
    cle_auto = input("Clé (cliquer sur 'Entrée' pour générer automatiquement) : ")
    
    if cle_auto:
        if len(cle_auto) < len(texte):
            print("Erreur : La clé saisie est trop courte. Elle doit faire au moins la taille du mot de passe.")
            return 
            
        key = cle_auto
        chiffre = xor_encrypt(texte, key)
    else:
        key, chiffre = chiffrerVernam(texte)
        
    print(f"Clé : {key}")
    print(f"Chiffré : {repr(chiffre)}")
    
    clair = DechiffrerVernam(chiffre, key)
    print(f"Déchiffré : {clair}")

def run_rc4():
    texte = input("text a chiffrer : ")
    cle = input("Clé RC4 : ")
    chiffre = RC4(texte, cle)
    print(f"Chiffré : {repr(chiffre)}")
    clair = RC4(chiffre, cle)
    print(f"Déchiffré : {clair}")

def run_des():
    texte = input("Texte à chiffrer : ")
    cle = input("Clé : ")
    
    if not cle:
        cle = "secret12"
        print(f"Clé par défaut utilisée : {cle}")

    chiffre = des_process(texte, cle)
    print(f"\nChiffré (brut) : {repr(chiffre)}")

    clair = des_decrypt_process(chiffre, cle).rstrip()
    print(f"Déchiffré      : {clair}")

SYM_ALGOS = {
    "César": run_cesar,
    "Vigenère": run_vigenere,
    "Vernam (XOR)": run_vernam,
    "RC4": run_rc4,
    "DES (bloc 64 bits, clé 64 bits)": run_des
}

def test_symetrique():
    while True:
        print("\n--- Test des algorithmes symétriques ---")
        noms = list(SYM_ALGOS.keys())
        for i, name in enumerate(noms, 1):
            print(f"{i}. {name}")
        print("0. Retour")
        
        choix = input("Choisissez un algorithme : ")
        
        if choix == "0":
            break

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
    print("\n--- Algorithme ElGamal ---")
    p = int(input("Premier p (p > 255, par ex 307) : "))
    g = int(input("Générateur g : "))
    
   
    if est_premier(p) and 1 < g < p:
        
       
        public_key, private_key = generate_keys(p, g)
        print("Clé publique :", public_key)
        print("Clé privée   :", private_key)

        texte = input("Message : ")
        bytes_msg = texte.encode('utf-8')
        
   
        c_list = [elgamal_encrypt(public_key, b) for b in bytes_msg]
        print(f"Chiffré      : {c_list}")
        
     
        m_dechiffre = bytes([elgamal_decrypt(private_key, public_key, c1, c2) for c1, c2 in c_list]).decode('utf-8')
        print(f"Déchiffré    : {m_dechiffre}")
        
    else:
        print("Erreur : 'p' doit être un nombre premier valide et 'g' doit être compris entre 1 et p.")
ASYM_ALGOS = {
    "RSA": run_rsa,
    "EC El GAMAL": run_ec_elgamal,
    "ElGamal": run_elgamal
}

def test_asymetrique():
    while True:
        print("\n--- Test des algorithmes asymétriques ---")
        noms = list(ASYM_ALGOS.keys())
        for i, name in enumerate(noms, 1):
            print(f"{i}. {name}")
        print("0. Retour")
        
        choix = input("Choisissez un algorithme : ")

        if choix == "0":
            break 
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
    
#fin
