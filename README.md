# Projet de développement de Malware

Ce projet a été développé dans le cadre du module "Hacking éthique et forensique Informatique". Le but est de réaliser créer un programme en C qui simule l'injection d'un payload récupéré sur un serveur web dans un processus sur le système cible.

## Membres du groupe

- Hugo BOURGET
- Jeremy GUILLERMIN
- Vincent CADORET

## Fonctionnement

- Récupération d'un shellcode depuis un serveur web. (Utilisation de **winhttp**).
- Conversion du string récupéré sur le serveur web en byte array pour rendre le shellcode fonctionnel.
- API Hashing des fonctions windows (NtOpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread).
- Injection et exécution du payload dans un processus distant (`explorer.exe`). Le payload lance `notepad.exe`

## Installation

- Installer `chocolatey` : https://chocolatey.org/install (Dans un powershell en Admin)
- Installer mingw et make : `choco install make` et `choco install mingw`
- Entrer "A" (all) lors de l'install de mingw
- cd `MalwareDev`
- `make` (Penser à rouvrir un nouveau shell pour que le PATH se refresh)
- Lancer un simple serveur web python à la racine du projet : `py -m http.server 80` 
- Executer le .exe générer par la commande `make`
