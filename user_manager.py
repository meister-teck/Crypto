import json
import os
from hash_algorithms import *
from symmetric_algorithms import *

USERS_FILE = "users.json"

HASH_METHODS = {
    "sha256": sha256,
    "sha1": sha1
}

ENCRYPT_METHODS = {
    "cesar": lambda p, k: chiffrerCesar(p, int(k)),
    "vigenere": chiffrerVigenere,
    "vernam": xor_encrypt,
    "rc4": lambda p, k: RC4(k, p),
    "des": des_process
}

def process_password(password, method="hash", algo="sha256", key=None):
    if method == "hash":
        func = HASH_METHODS.get(algo)
        if func: return func(password)
    elif method == "encrypt":
        func = ENCRYPT_METHODS.get(algo)
        if func: return func(password, key)
    return password

def load_users():
    if not os.path.exists(USERS_FILE) or os.path.getsize(USERS_FILE) == 0:
        admin_data = process_password("admin123", "hash", "sha256")
        admin = {
            "username": "admin",
            "password_hash": admin_data,
            "role": "admin",
            "storage_method": "hash",
            "algorithm": "sha256"
        }
        users = {"admin": admin}
        save_users(users)
        print("[SYSTEME] Compte admin créé : admin / admin123")
        return users
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

def create_user(users, username, password, role="user", method="hash", algo="sha256", key=None):
    if username in users:
        print("Erreur : utilisateur existe déjà.")
        return False
    users[username] = {
        "username": username,
        "password_hash": process_password(password, method, algo, key),
        "role": role,
        "storage_method": method,
        "algorithm": algo
    }
    if key is not None:
        users[username]["key"] = key
    save_users(users)
    print(f"Utilisateur '{username}' créé (Méthode: {method}, Algo: {algo}).")
    return True

def modify_user(users, username, new_password=None, new_role=None):
    if username not in users:
        print("Utilisateur inconnu.")
        return False
    if new_password:
        method = users[username].get("storage_method", "hash")
        algo = users[username].get("algorithm", "sha256")
        key = users[username].get("key", None)
        users[username]["password_hash"] = process_password(new_password, method, algo, key)
    if new_role and new_role in ["admin", "user"]:
        users[username]["role"] = new_role
    save_users(users)
    print(f"Utilisateur '{username}' modifié.")
    return True

def delete_user(users, username, current_username):
    if username == current_username:
        print("Impossible de supprimer son propre compte.")
        return False
    if username not in users:
        print("Utilisateur inconnu.")
        return False
    del users[username]
    save_users(users)
    print(f"Utilisateur '{username}' supprimé.")
    return True

def authenticate(users, username, password):
    if username not in users:
        return None
    user = users[username]
    method = user.get("storage_method", "hash")
    algo = user.get("algorithm", "sha256")
    key = user.get("key", None)
    
    if process_password(password, method, algo, key) == user["password_hash"]:
        return user
    return None