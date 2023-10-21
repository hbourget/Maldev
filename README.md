# Projet de développement de Malware

Ce projet a été développé dans le cadre du module "Hacking éthique et forensique Informatique". Le but est de réaliser créer un programme en C qui simule l'injection d'un payload récupéré sur un serveur web dans un processus sur le système cible.

## Membres du groupe

- Hugo BOURGET
- Jeremy GUILLERMIN
- Vincent CADORET

## Fonctionnement

- Récupération d'un shellcode depuis un serveur web. (Utilisation de **winhttp**).
- Convertion du string récupéré sur le serveur web en byte array.
- API Hashing des fonctions windows (NtOpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread).
- Injection et exécution du payload dans un processus distant (`explorer.exe`).

## Installation

- Installer `chocolatey` : https://chocolatey.org/install (Dans un powershell en Admin)
- Installer mingw et make : `choco install make` et `choco install mingw`
- Entrer "A" (all) lors de l'install de mingw
- cd `MalwareDev`
- `make`
- Lancer un simple serveur web python à la racine du projet : `py -m http.server 80` 
- Lancer le .exe générer par la commande `make`
- Le payload lance un bloc-notes (notepad.exe)