# Déploiement S3 sur la VM (collecteur + API)

## 1. Installer
    cd ~/cabinetshield
    tar xzf ~/s3-collecteur-api.tar.gz
    sudo apt install -y python3-flask
    python3 -m unittest discover -s tests          # 45 tests, doit finir par OK

## 2. Jeton (hors dépôt Git)
    mkdir -p ~/.config/cabinetshield && chmod 700 ~/.config/cabinetshield
    python3 -c "import secrets; print(secrets.token_urlsafe(32))" > ~/.config/cabinetshield/jeton
    chmod 600 ~/.config/cabinetshield/jeton

## 3. Lancer (2 terminaux)
    # terminal 1 : collecteur (lit eve.json, besoin de sudo ou du groupe qui lit /var/log/suricata)
    sudo python3 -m collector --db ~/cabinetshield/data/cabinetshield.db
    # terminal 2 : API
    python3 -m api --token-file ~/.config/cabinetshield/jeton

## 4. Démo bout en bout
    sudo ./scripts/creer-dummy0.sh                  # si dummy0 a disparu après redémarrage
    sudo tcpreplay -i dummy0 tests/data/demo.pcap   # ou la commande habituelle de rejeu
    J=$(cat ~/.config/cabinetshield/jeton)
    curl -s localhost:5000/api/health
    curl -s -H "Authorization: Bearer $J" localhost:5000/api/summary
    curl -s -H "Authorization: Bearer $J" "localhost:5000/api/alerts?gravite=eleve"
