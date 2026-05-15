import json
import os
from hash_algorithms import sha256

USERS_FILE = "users.json"

def hash_password(password):
    return sha256(password)

def verify_password(password, stored_hash):
    return hash_password(password) == stored_hash

def load_users():
    if not os.path.exists(USERS_FILE):
        admin_hash = hash_password("admin123")
        admin = {
            "username": "admin",
            "password_hash": admin_hash,
            "role": "admin"
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

def create_user(users, username, password, role="user"):
    if username in users:
        print("Erreur : utilisateur existe déjà.")
        return False
    users[username] = {
        "username": username,
        "password_hash": hash_password(password),
        "role": role
    }
    save_users(users)
    print(f"Utilisateur '{username}' créé.")
    return True

def modify_user(users, username, new_password=None, new_role=None):
    if username not in users:
        print("Utilisateur inconnu.")
        return False
    if new_password:
        users[username]["password_hash"] = hash_password(new_password)
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
    if verify_password(password, user["password_hash"]):
        return user
    return None