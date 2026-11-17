"""Lancement : CS_TOKEN=... python3 -m api [--db ...] [--host 127.0.0.1] [--port 5000]

Le jeton se donne par la variable d'environnement CS_TOKEN ou par --token-file
(fichier hors dépôt Git, droits 600). Jamais en argument de ligne de commande.
"""
import argparse
import os
import sys
from pathlib import Path

from .app import create_app

RACINE = Path(__file__).resolve().parent.parent


def main():
    p = argparse.ArgumentParser(description="CabinetShield : API REST")
    p.add_argument("--db", default=os.environ.get("CS_DB", str(RACINE / "data" / "cabinetshield.db")))
    p.add_argument("--host", default="127.0.0.1", help="127.0.0.1 par défaut (non exposée)")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--token-file", help="fichier contenant le jeton")
    args = p.parse_args()

    jeton = (Path(args.token_file).read_text().strip() if args.token_file
             else os.environ.get("CS_TOKEN", ""))
    try:
        app = create_app(args.db, jeton)
    except ValueError as e:
        sys.exit(f"Erreur : {e}. Génération : python3 -c \"import secrets; print(secrets.token_urlsafe(32))\"")
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
