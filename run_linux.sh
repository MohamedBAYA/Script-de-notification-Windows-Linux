#!/bin/bash

echo "[*] Installation des dépendances pour Linux..."

# Mise à jour des dépôts
sudo apt update -y

# Installation Python + libnotify
sudo apt install -y python3 python3-pip libnotify-bin

echo "[*] Installation des dépendances Python..."
pip3 install -r install/requirements_linux.txt 2>/dev/null

echo "[*] Lancement du script de détection..."
sudo python3 src/detect_intrusionV1-0.py