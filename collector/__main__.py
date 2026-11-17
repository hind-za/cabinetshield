"""Lancement : python3 -m collector [--eve ...] [--db ...] [--une-fois]"""
import argparse
import logging
import os
from pathlib import Path

from .collecteur import Collecteur

RACINE = Path(__file__).resolve().parent.parent


def main():
    p = argparse.ArgumentParser(description="CabinetShield : collecteur eve.json -> SQLite")
    p.add_argument("--eve", default=os.environ.get("CS_EVE", "/var/log/suricata/eve.json"))
    p.add_argument("--db", default=os.environ.get("CS_DB", str(RACINE / "data" / "cabinetshield.db")))
    p.add_argument("--schema", default=str(RACINE / "docs" / "schema.sql"))
    p.add_argument("--intervalle", type=float, default=1.0, help="secondes entre deux passages")
    p.add_argument("--une-fois", action="store_true", help="un seul passage puis arrêt")
    args = p.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    c = Collecteur(args.eve, args.db, args.schema)
    if args.une_fois:
        print(c.cycle())
        c.base.fermer()
    else:
        c.boucle(args.intervalle)


if __name__ == "__main__":
    main()
