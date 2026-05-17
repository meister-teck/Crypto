# Gestionnaire de mots de passe & Cryptographie (Projet Python)

## Description

Application console en Python qui permet de gérer des utilisateurs (admin / user) et de tester interactivement plusieurs algorithmes de chiffrement symétrique et de hachage, implémentés manuellement (sans bibliothèques externes).  
L’administrateur peut créer, modifier ou supprimer des comptes. Chaque utilisateur peut tester les algorithmes et l’authentification se fait par hachage SHA256 maison.

## Fonctionnalités

- **Gestion des utilisateurs** (CRUD) avec rôles (admin / user)
- **Chiffrement symétrique** :  
  - César, Vigenère, Vernam (XOR), RC4, DES (Feistel, S-Box)
- **Chiffrement symétrique** :
  - RSA , ElGamal
- **Modes de chiffrement** : CFB, CBC, OFB (pour les blocs)
- **Hachage** : SHA1 et SHA256 (implémentations personnelles)
- **Stockage** : JSON pour les utilisateurs (mots de passe hachés)

## Installation

1. Clonez le dépôt :
   ```bash
   git clone https://github.com/votre-utilisateur/votre-repo.git
   cd votre-repo
