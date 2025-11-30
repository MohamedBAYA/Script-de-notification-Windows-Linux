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

#### Étape 1 - Clonez le dépôt sur Linux (Ubuntu/Debian)

```bash
sudo apt install git -y
git clone https://github.com/MohamedBAYA/Script-de-notification-Windows-Linux.git
cd Script-de-notification-Windows-Linux
```

#### Étape 2 : Lancez l'installation automatique

```bash
chmod +x install/setup.sh
./install/setup.sh
```

### Ce script va :

- Installer les dépendances système (python3, libnotify, openssh-server, etc.)
- Créer et configurer l'environnement virtuel
- Ajuster les permissions sur les répertoires

**Note :** Sur la partie Linux, `python3.12-venv` est requis pour créer un environnement virtuel.

#### Étape 3 : Créez et activez l'environnement virtuel

```bash
python3 -m venv venv
source venv/bin/activate
```

#### Étape 4 : Lancer le script principal

```bash
python src/detect_intrusionV1-0.py
```

**Pour tester les alertes :**
Ouvrez un deuxième terminal et lancez :

```bash
ssh test@localhost
(Entrez un mot de passe incorrect pour générer une alerte)
```

Ou vous pouvez également le faire depuis une autre machine en ciblant l'IP de la machine où le script tourne :

```bash
ssh test@<IP_de_la_machine>
(Entrez un mot de passe incorrect pour générer une alerte)
```

### Vous devriez recevoir une notification de bureau indiquant une tentative d'intrusion.

Exemple de notification sous Linux :
![Notification Linux](img/Exemple.png)

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
