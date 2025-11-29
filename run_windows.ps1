Write-Host "[*] Installation des dépendances Windows..." -ForegroundColor Cyan

# Installation des modules Python nécessaires
pip install -r install/requirements_windows.txt

Write-Host "[*] Lancement du script de détection..." -ForegroundColor Green
python src/detect_intrusionV1-0.py