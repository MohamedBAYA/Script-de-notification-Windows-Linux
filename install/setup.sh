#!/bin/bash
set -e

echo "[*] Détection de l'OS..."

OS=$(uname -s)

if [ "$OS" = "Linux" ]; then
    echo "[*] Installation des dépendances pour Linux..."
    sudo apt update -y
    sudo apt install -y python3 python3-pip python3.12-venv libnotify-bin openssh-server
    
    echo "[*] Activation du service SSH..."
    sudo systemctl enable --now ssh
    
    echo "[*] Ajustement des droits sur les répertoires..."
    REAL_USER=${SUDO_USER:-$(whoami)}
    sudo chown -R $REAL_USER:$REAL_USER logs/
    sudo chown -R $REAL_USER:$REAL_USER config/
    
    echo "[*] Installation terminée."
    echo "[*] Pour lancer le script :"
    echo "    source venv/bin/activate"
    echo "    python src/detect_intrusionV1-0.py"
    
else
    echo "[ERREUR] OS non supporté par ce script d'installation."
    exit 1
fi
