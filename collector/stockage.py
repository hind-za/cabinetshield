"""Accès SQLite du collecteur (requêtes toujours paramétrées)."""
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

# Décision proposée dans docs/gravites.md, à valider à deux :
# une alerte « traitee » qui revient repasse à « a_examiner » (et c'est tracé dans admin_log).
REOUVRIR_SI_TRAITEE = True


def maintenant_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Base:
    def __init__(self, chemin_db, chemin_schema):
        chemin_db = Path(chemin_db)
        chemin_db.parent.mkdir(parents=True, exist_ok=True)
        # timeout : l'API peut lire en même temps (mode WAL)
        self.conn = sqlite3.connect(str(chemin_db), timeout=10)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(Path(chemin_schema).read_text(encoding="utf-8"))
        self.conn.execute("PRAGMA foreign_keys = ON")

    def fermer(self):
        self.conn.close()

    # --- état du collecteur (une seule ligne, id = 1) -------------------
    def lire_etat(self):
        return self.conn.execute("SELECT * FROM collector_state WHERE id = 1").fetchone()

    def ecrire_etat(self, *, inode, offset, dernier_evenement, nb_erreurs, derniere_erreur):
        """Met à jour la position de lecture et la santé. À appeler dans la transaction."""
        self.conn.execute(
            """UPDATE collector_state SET
                   fichier_inode = ?, offset_octets = ?, dernier_cycle = ?,
                   dernier_evenement = COALESCE(?, dernier_evenement),
                   erreurs_lecture = erreurs_lecture + ?,
                   derniere_erreur = COALESCE(?, derniere_erreur)
               WHERE id = 1""",
            (inode, offset, maintenant_utc(), dernier_evenement, nb_erreurs, derniere_erreur),
        )

    def signaler_erreur(self, message):
        """Erreur hors lecture de lignes (ex. fichier introuvable) : incrémente le compteur."""
        self.conn.execute(
            """UPDATE collector_state SET dernier_cycle = ?,
                   erreurs_lecture = erreurs_lecture + 1, derniere_erreur = ?
               WHERE id = 1""",
            (maintenant_utc(), message),
        )
        self.conn.commit()

    def signal_de_vie(self):
        self.conn.execute(
            "UPDATE collector_state SET dernier_cycle = ? WHERE id = 1", (maintenant_utc(),)
        )
        self.conn.commit()

    # --- alertes ---------------------------------------------------------
    def enregistrer_alerte(self, a):
        """Insère ou incrémente (déduplication). Retourne 'creee', 'incrementee' ou 'reouverte'.

        Ne fait pas de commit : l'appelant groupe les alertes et l'offset dans une transaction.
        """
        maintenant = maintenant_utc()
        ligne = self.conn.execute(
            "SELECT id, statut FROM alerts WHERE cle_dedup = ?", (a["cle_dedup"],)
        ).fetchone()

        if ligne is None:
            self.conn.execute(
                """INSERT INTO alerts
                   (cle_dedup, premiere_vue, derniere_vue, compteur, signature, signature_id,
                    categorie, proto, src_ip, src_port, dest_ip, dest_port, gravite_suricata,
                    gravite, confiance, explication, action_recommandee, statut, maj_le)
                   VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'a_examiner', ?)""",
                (a["cle_dedup"], a["horodatage"], a["horodatage"], a["signature"],
                 a["signature_id"], a["categorie"], a["proto"], a["src_ip"], a["src_port"],
                 a["dest_ip"], a["dest_port"], a["gravite_suricata"], a["gravite"],
                 a["confiance"], a["explication"], a["action_recommandee"], maintenant),
            )
            return "creee"

        reouverte = REOUVRIR_SI_TRAITEE and ligne["statut"] == "traitee"
        # derniere_vue ne recule jamais (événements relus dans le désordre)
        self.conn.execute(
            """UPDATE alerts SET compteur = compteur + 1,
                   derniere_vue = MAX(derniere_vue, ?), src_port = ?, maj_le = ?,
                   statut = CASE WHEN ? THEN 'a_examiner' ELSE statut END
               WHERE id = ?""",
            (a["horodatage"], a["src_port"], maintenant, 1 if reouverte else 0, ligne["id"]),
        )
        if reouverte:
            self.conn.execute(
                "INSERT INTO admin_log (horodatage, action, alerte_id, detail) VALUES (?,?,?,?)",
                (maintenant, "reouverture_alerte", ligne["id"],
                 "alerte traitee revenue : statut remis a a_examiner"),
            )
            return "reouverte"
        return "incrementee"
