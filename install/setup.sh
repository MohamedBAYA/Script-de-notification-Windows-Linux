#!/bin/bash
set -e

echo "[*] Détection de l'OS..."

OS=$(uname -s)

if [ "$OS" = "Linux" ]; then
    echo "[*] Installation des dépendances pour Linux..."
    sudo apt update -y
    sudo apt install -y python3 python3-pip libnotify-bin
    
    echo "[*] Installation des dépendances Python..."
    pip3 install -r install/requirements_linux.txt
    
    echo "[*] Lancement du script de détection..."
    sudo python3 src/detect_intrusionV1-0.py
    
else
    echo "[ERREUR] OS non supporté par ce script d'installation."
    exit 1
fi
echo "[*] Installation terminée."