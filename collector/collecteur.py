"""Boucle de collecte : lit eve.json, normalise, déduplique, stocke.

Garanties :
- Un JSON invalide ou un champ absent ne fait jamais planter le collecteur
  (la ligne est ignorée, comptée dans collector_state.erreurs_lecture).
- La position de lecture (inode + offset) est écrite dans la MÊME transaction que les
  alertes : un arrêt brutal ne provoque ni perte ni doublon.
- Une ligne incomplète (sans retour à la ligne final) n'est lue que lorsqu'elle est terminée.
"""
import json
import logging
import os
import signal
import sqlite3
import threading

from .normaliser import ErreurEvenement, normaliser
from .stockage import Base

log = logging.getLogger("cabinetshield.collecteur")

TAILLE_LOT = 1024 * 1024  # on lit eve.json par lots d'environ 1 Mo (mémoire bornée)


class Collecteur:
    def __init__(self, chemin_eve, chemin_db, chemin_schema):
        self.chemin_eve = str(chemin_eve)
        self.base = Base(chemin_db, chemin_schema)
        self._arret = threading.Event()

    # ------------------------------------------------------------------
    def cycle(self):
        """Un passage : lit tout ce qui est nouveau. Retourne des statistiques."""
        stats = {"lignes": 0, "alertes": 0, "creees": 0, "incrementees": 0,
                 "reouvertes": 0, "ignorees": 0}
        try:
            fichier = open(self.chemin_eve, "rb")
        except OSError as e:
            message = f"eve.json illisible : {e.strerror or e}"
            if self.base.lire_etat()["derniere_erreur"] != message:  # pas de bruit à chaque cycle
                log.warning(message)
                self.base.signaler_erreur(message)
            else:
                self.base.signal_de_vie()
            return stats

        with fichier:
            st = os.fstat(fichier.fileno())
            etat = self.base.lire_etat()
            offset = etat["offset_octets"]
            inode_connu = etat["fichier_inode"]

            if inode_connu is not None and inode_connu != st.st_ino:
                log.info("rotation détectée (nouvel inode) : relecture depuis le début")
                offset = 0
            elif st.st_size < offset:
                log.info("fichier tronqué : relecture depuis le début")
                offset = 0

            if offset != etat["offset_octets"] or inode_connu != st.st_ino:
                self.base.ecrire_etat(inode=st.st_ino, offset=offset, dernier_evenement=None,
                                      nb_erreurs=0, derniere_erreur=None)
                self.base.conn.commit()

            fichier.seek(offset)
            vu_quelque_chose = False
            while True:
                lignes = fichier.readlines(TAILLE_LOT)
                if not lignes:
                    break
                try:
                    offset = self._traiter_lot(lignes, offset, st.st_ino, stats)
                except sqlite3.Error:
                    self.base.conn.rollback()
                    raise
                vu_quelque_chose = True
                if not lignes[-1].endswith(b"\n"):
                    break  # ligne incomplète en fin de fichier : on attend la suite

        if not vu_quelque_chose or stats["lignes"] == 0:
            self.base.signal_de_vie()
        return stats

    # ------------------------------------------------------------------
    def _traiter_lot(self, lignes, offset, inode, stats):
        dernier_evenement = None
        nb_erreurs = 0
        derniere_erreur = None

        for brute in lignes:
            if not brute.endswith(b"\n"):
                break  # incomplète : on ne l'avance pas dans l'offset
            offset += len(brute)
            if not brute.strip():
                continue
            stats["lignes"] += 1
            try:
                evenement = json.loads(brute)
                horodatage, alerte = normaliser(evenement)
            except (ValueError, ErreurEvenement) as e:  # JSONDecodeError est un ValueError
                nb_erreurs += 1
                stats["ignorees"] += 1
                derniere_erreur = f"ligne ignorée : {e}"[:200]
                log.warning(derniere_erreur)
                continue

            dernier_evenement = horodatage
            if alerte is None:
                continue  # stats, flow, dns... : pas des alertes
            stats["alertes"] += 1
            resultat = self.base.enregistrer_alerte(alerte)
            stats[{"creee": "creees", "incrementee": "incrementees",
                   "reouverte": "reouvertes"}[resultat]] += 1

        self.base.ecrire_etat(inode=inode, offset=offset, dernier_evenement=dernier_evenement,
                              nb_erreurs=nb_erreurs, derniere_erreur=derniere_erreur)
        self.base.conn.commit()  # alertes + offset validés ensemble
        return offset

    # ------------------------------------------------------------------
    def arreter(self, *_):
        self._arret.set()

    def boucle(self, intervalle=1.0):
        signal.signal(signal.SIGTERM, self.arreter)
        signal.signal(signal.SIGINT, self.arreter)
        log.info("collecteur démarré : %s", self.chemin_eve)
        while not self._arret.is_set():
            try:
                stats = self.cycle()
                if stats["lignes"]:
                    log.info("cycle : %s", stats)
            except Exception:  # le collecteur ne doit jamais s'arrêter sur une erreur imprévue
                log.exception("erreur pendant le cycle (on réessaie au prochain)")
            self._arret.wait(intervalle)
        self.base.fermer()
        log.info("collecteur arrêté proprement")
