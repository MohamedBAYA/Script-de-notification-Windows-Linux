# Blue Team – Intrusion Detection Script (Windows & Linux)

## 🐍 Prérequis

Ce projet nécessite :

- Python 3.10+
- Les dépendances mentionnées dans `install/requirements_windows.txt` ou `install/requirements_linux.txt`

### Installer Python

Télécharge Python depuis le site officiel :  
➡️ https://www.python.org/downloads/

⚠️ Sur Windows, cocher la case : “Add Python to PATH” lors de l'installation.

Ce projet fournit un script Python universel permettant de détecter à titre d’exemple (POC) :

- des tentatives d’authentification SSH échouées sous Linux
- des échecs de connexion Windows (Event ID 4625)

Le script s’adapte automatiquement à l’OS sur lequel il s’exécute (Windows ou Linux) et génère une notification locale en cas de tentative d’intrusion.

---

## 🚀 Installation & utilisation

### Linux (Ubuntu/Debian)

```bash
git clone <URL_DU_REPO>
cd Script-de-notification-Windows-Linux
```

### Option 1 – Script d’installation complet :

```bash
chmod +x install/setup.sh
./install/setup.sh
```

### Option 2 – Manuel (si vous préférez garder le contrôle) :

```bash
chmod +x run_linux.sh
./run_linux.sh
```

---

### Windows 10

1. Cloner le dépôt (via Git ou téléchargement ZIP).
2. Ouvrir PowerShell en tant qu’administrateur.
3. Se placer dans le dossier du projet :

```powershell
cd Script-de-notification-Windows-Linux
```

### Installer les dépendances Python :

```powershell
python -m pip install -r install/requirements_windows.txt
```

### Lancer le script :

```powershell
.\run_windows.ps1
```

---

## Structure du projet

```bash
src/
└── detect_intrusionV1-0.py     # Script principal (universel Windows + Linux)

install/
├── requirements_linux.txt      # Dépendances Python Linux
├── requirements_windows.txt    # Dépendances Python Windows
└── setup.sh                    # Script d’installation + lancement Linux

config/
└── config.example.json         # Exemple de configuration

logs/
└── intrusion_detection.log     # Fichier de logs (créé au runtime)

run_linux.sh                    # Lanceur Linux (alternative à install/setup.sh)
run_windows.ps1                 # Lanceur Windows
README.md                       # Ce fichier
```

## Objectif

Fournir un outil Blue Team simple, portable sur plusieurs OS permettant d’être alerté localement en cas de tentative d’intrusion via une notification de bureau.

## Auteur

- Mohamed BAYA – Étudiant ESGI 5ème année (5SI3) – Blue Team SOC – T1 2025
