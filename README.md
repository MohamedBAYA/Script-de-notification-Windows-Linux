# Blue Team – Intrusion Detection Script (Windows & Linux)

## 🐍 Prérequis

Ce projet nécessite :

- **Python 3.10+**
- Les dépendances mentionnées dans `install/requirements_windows.txt` ou `install/requirements_linux.txt`

### Installer Python

Télécharge Python depuis le site officiel :
➡️ [https://www.python.org/downloads/](https://www.python.org/downloads/)

⚠️ Sur Windows, cocher la case : “Add Python to PATH” lors de l'installation.

Ce projet fournit **un script Python universel** permettant de détecter à titre d’exemple (POC) :

- des tentatives d’authentification SSH échouées sous Linux
- des échecs de connexion Windows (Event ID 4625)

Le script **s’adapte automatiquement** à l’OS sur lequel il s’exécute (Windows ou Linux) et génère une notification locale en cas de tentative d’intrusion.

---

## Structure du projet

```txt
src/
└── detect_intrusion.py       # Script principal (universel Windows + Linux)

install/
├── requirements_linux.txt    # Dépendances Linux
└── requirements_windows.txt  # Dépendances Windows

run_linux.sh                  # Lanceur Linux
run_windows.ps1               # Lanceur Windows
```

## Objectif

Fournir un outil Blue Team simple, portable sur plusieurs OS permettant d’être alerté localement en cas de tentative d’intrusion via une notification de bureau.

## Auteur

- Mohamed BAYA – Étudiant ESGI 5ème année (5SI3) – Blue Team SOC – T1 2025
