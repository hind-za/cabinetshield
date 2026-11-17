"""Tests unitaires du collecteur. Lancement : python3 -m unittest discover -s tests -v"""
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE))

from collector.collecteur import Collecteur  # noqa: E402
from collector.normaliser import ErreurEvenement, normaliser, vers_utc  # noqa: E402
from collector import stockage  # noqa: E402

SCHEMA = RACINE / "docs" / "schema.sql"
ECHANTILLON = RACINE / "tests" / "data" / "eve_alerts_sample.json"


def evenement(sid=2000001, severite=2, categorie="Misc Activity", port=22, src_port=40000,
              ts="2026-10-26T12:39:49.746229-0400", signature="TEST sig"):
    return {"timestamp": ts, "event_type": "alert", "src_ip": "10.0.0.1", "src_port": src_port,
            "dest_ip": "10.0.0.2", "dest_port": port, "proto": "TCP",
            "alert": {"signature_id": sid, "signature": signature, "category": categorie,
                      "severity": severite}}


class Base(unittest.TestCase):
    def setUp(self):
        self.dossier = Path(tempfile.mkdtemp())
        self.eve = self.dossier / "eve.json"
        self.db = self.dossier / "test.db"
        self.eve.write_bytes(b"")

    def tearDown(self):
        shutil.rmtree(self.dossier, ignore_errors=True)

    def collecteur(self):
        return Collecteur(self.eve, self.db, SCHEMA)

    def ajouter(self, *lignes):
        with open(self.eve, "ab") as f:
            for l in lignes:
                f.write((l if isinstance(l, bytes) else
                         (l if isinstance(l, str) else json.dumps(l)).encode()) + b"\n")

    def sql(self, requete, params=()):
        conn = sqlite3.connect(self.db)
        conn.row_factory = sqlite3.Row
        try:
            return conn.execute(requete, params).fetchall()
        finally:
            conn.close()


class TestNormalisation(unittest.TestCase):
    def test_heure_convertie_en_utc(self):
        self.assertEqual(vers_utc("2026-10-26T12:39:49.746229-0400"), "2026-10-26T16:39:49Z")

    def test_timestamp_absent_leve_erreur(self):
        with self.assertRaises(ErreurEvenement):
            normaliser({"event_type": "alert"})

    def test_evenement_non_alerte_ignore(self):
        ts, a = normaliser({"timestamp": "2026-10-26T12:00:00+0000", "event_type": "stats"})
        self.assertIsNone(a)
        self.assertEqual(ts, "2026-10-26T12:00:00Z")

    def test_champs_absents_ne_plantent_pas(self):
        _, a = normaliser({"timestamp": "2026-10-26T12:00:00+0000", "event_type": "alert",
                           "alert": {}})
        self.assertEqual(a["signature"], "Signature inconnue")
        self.assertEqual((a["gravite"], a["confiance"]), ("moyen", "faible"))  # règle 4
        self.assertIsNone(a["dest_port"])

    def test_cle_dedup_sans_port_source(self):
        _, a = normaliser(evenement(sid=1000002, src_port=1111))
        _, b = normaliser(evenement(sid=1000002, src_port=2222))
        self.assertEqual(a["cle_dedup"], b["cle_dedup"])
        self.assertEqual(a["cle_dedup"], "1000002|10.0.0.1|10.0.0.2|22")

    def test_regles_de_gravite(self):
        def g(**kw):
            _, a = normaliser(evenement(**kw))
            return a["gravite"], a["confiance"]
        # 1. dictionnaire par signature_id
        self.assertEqual(g(sid=1000003, severite=3), ("eleve", "elevee"))
        # 2. catégorie not-suspicious
        self.assertEqual(g(categorie="Not Suspicious Traffic", severite=1), ("informatif", "moyenne"))
        # 3. gravité Suricata, catégorie connue / inconnue
        self.assertEqual(g(categorie="Web Application Attack", severite=2), ("moyen", "moyenne"))
        self.assertEqual(g(categorie="Inconnue", severite=1), ("eleve", "faible"))
        self.assertEqual(g(categorie="Inconnue", severite=3), ("faible", "faible"))
        # 4. rien d'exploitable
        self.assertEqual(g(categorie=None, severite=None), ("moyen", "faible"))
        self.assertEqual(g(categorie="Inconnue", severite=9), ("moyen", "faible"))

    def test_explications_jamais_une_preuve(self):
        interdits = ("attaque prouvée", "est compromis", "a été piraté", "est infecté",
                     "preuve que", "vous êtes attaqué", "intrusion confirmée")
        for sid in (1000001, 1000002, 1000003, None):
            for categorie in (None, "A Network Trojan was detected", "Web Application Attack"):
                _, a = normaliser(evenement(sid=sid, categorie=categorie, severite=1))
                texte = (a["explication"] + " " + a["action_recommandee"]).lower()
                for mot in interdits:
                    self.assertNotIn(mot, texte)


class TestCollecteur(Base):
    def test_evenement_valide_collecte_et_stocke(self):
        self.ajouter(evenement(sid=1000003, severite=1, port=4444))
        c = self.collecteur()
        stats = c.cycle()
        self.assertEqual((stats["lignes"], stats["creees"]), (1, 1))
        lignes = self.sql("SELECT * FROM alerts")
        self.assertEqual(len(lignes), 1)
        self.assertEqual(lignes[0]["gravite"], "eleve")
        self.assertEqual(lignes[0]["statut"], "a_examiner")
        self.assertEqual(lignes[0]["derniere_vue"], "2026-10-26T16:39:49Z")
        c.base.fermer()

    def test_json_invalide_ne_plante_pas(self):
        self.ajouter("{ceci n'est pas du json", b"\xff\xfe\x00 octets invalides",
                     "[1, 2, 3]", evenement(), '{"event_type":"alert"}')
        c = self.collecteur()
        stats = c.cycle()
        self.assertEqual(stats["creees"], 1)       # la bonne ligne est quand même traitée
        self.assertEqual(stats["ignorees"], 4)
        etat = self.sql("SELECT * FROM collector_state")[0]
        self.assertEqual(etat["erreurs_lecture"], 4)
        self.assertIn("ligne ignorée", etat["derniere_erreur"])
        c.base.fermer()

    def test_n_evenements_identiques_donnent_une_alerte(self):
        N = 7
        self.ajouter(*[evenement(sid=1000002, src_port=40000 + i, ts=f"2026-10-26T12:39:{10+i}-0400")
                       for i in range(N)])
        c = self.collecteur()
        c.cycle()
        lignes = self.sql("SELECT * FROM alerts")
        self.assertEqual(len(lignes), 1)
        self.assertEqual(lignes[0]["compteur"], N)
        self.assertEqual(lignes[0]["premiere_vue"], "2026-10-26T16:39:10Z")
        self.assertEqual(lignes[0]["derniere_vue"], "2026-10-26T16:39:16Z")
        c.base.fermer()

    def test_echantillon_reel(self):
        shutil.copy(ECHANTILLON, self.eve)
        c = self.collecteur()
        stats = c.cycle()
        self.assertEqual((stats["lignes"], stats["creees"], stats["incrementees"]), (4, 3, 1))
        par_sid = {r["signature_id"]: r for r in self.sql("SELECT * FROM alerts")}
        self.assertEqual(par_sid[1000001]["gravite"], "informatif")
        self.assertEqual((par_sid[1000002]["gravite"], par_sid[1000002]["compteur"]), ("moyen", 2))
        self.assertEqual(par_sid[1000003]["gravite"], "eleve")
        self.assertEqual(par_sid[1000002]["confiance"], "elevee")
        c.base.fermer()

    def test_redemarrage_sans_perte_ni_doublon(self):
        self.ajouter(evenement(sid=1, ts="2026-10-26T12:00:01-0400"),
                     evenement(sid=2, ts="2026-10-26T12:00:02-0400"))
        c1 = self.collecteur()
        c1.cycle()
        c1.base.fermer()                                   # arrêt du collecteur
        self.ajouter(evenement(sid=3, ts="2026-10-26T12:00:03-0400"))   # écrit pendant l'arrêt
        c2 = self.collecteur()                             # redémarrage
        stats = c2.cycle()
        self.assertEqual(stats["lignes"], 1)               # seule la nouvelle ligne est lue
        self.assertEqual(c2.cycle()["lignes"], 0)          # rien de plus au passage suivant
        self.assertEqual(len(self.sql("SELECT * FROM alerts")), 3)
        self.assertEqual(sum(r["compteur"] for r in self.sql("SELECT * FROM alerts")), 3)
        c2.base.fermer()

    def test_ligne_incomplete_attendue(self):
        c = self.collecteur()
        morceau = json.dumps(evenement(sid=5)).encode()
        with open(self.eve, "ab") as f:
            f.write(morceau[:30])                           # Suricata n'a pas fini d'écrire
        self.assertEqual(c.cycle()["lignes"], 0)
        with open(self.eve, "ab") as f:
            f.write(morceau[30:] + b"\n")
        self.assertEqual(c.cycle()["creees"], 1)
        self.assertEqual(c.cycle()["lignes"], 0)
        self.assertEqual(self.sql("SELECT COUNT(*) AS n FROM collector_state")[0]["n"], 1)
        c.base.fermer()

    def test_rotation_du_fichier(self):
        self.ajouter(evenement(sid=1), evenement(sid=2))
        c = self.collecteur()
        c.cycle()
        os.rename(self.eve, self.dossier / "eve.json.1")   # rotation : nouveau fichier, nouvel inode
        self.eve.write_bytes(b"")
        self.ajouter(evenement(sid=3))
        self.assertEqual(c.cycle()["creees"], 1)
        self.assertEqual(len(self.sql("SELECT * FROM alerts")), 3)
        c.base.fermer()

    def test_fichier_tronque(self):
        self.ajouter(evenement(sid=1), evenement(sid=2))
        c = self.collecteur()
        c.cycle()
        self.eve.write_bytes(b"")                          # vidé sur place (même inode)
        self.ajouter(evenement(sid=3))
        self.assertEqual(c.cycle()["creees"], 1)
        c.base.fermer()

    def test_fichier_absent_puis_present(self):
        os.remove(self.eve)
        c = self.collecteur()
        c.cycle()
        c.cycle()
        etat = self.sql("SELECT * FROM collector_state")[0]
        self.assertEqual(etat["erreurs_lecture"], 1)       # compté une seule fois, pas à chaque cycle
        self.assertIn("illisible", etat["derniere_erreur"])
        self.ajouter(evenement())
        self.assertEqual(c.cycle()["creees"], 1)
        c.base.fermer()

    def test_signal_de_vie_sans_evenement(self):
        c = self.collecteur()
        c.cycle()
        self.assertIsNotNone(self.sql("SELECT dernier_cycle FROM collector_state")[0][0])
        c.base.fermer()

    def test_alerte_traitee_qui_revient_est_reouverte_et_tracee(self):
        self.ajouter(evenement(sid=7))
        c = self.collecteur()
        c.cycle()
        c.base.conn.execute("UPDATE alerts SET statut = 'traitee'")
        c.base.conn.commit()
        self.ajouter(evenement(sid=7))
        self.assertEqual(c.cycle()["reouvertes"], 1)
        self.assertEqual(self.sql("SELECT statut FROM alerts")[0][0], "a_examiner")
        self.assertEqual(self.sql("SELECT action FROM admin_log")[0][0], "reouverture_alerte")
        c.base.fermer()

    def test_alerte_en_cours_garde_son_statut(self):
        self.ajouter(evenement(sid=8))
        c = self.collecteur()
        c.cycle()
        c.base.conn.execute("UPDATE alerts SET statut = 'en_cours'")
        c.base.conn.commit()
        self.ajouter(evenement(sid=8))
        c.cycle()
        self.assertEqual(self.sql("SELECT statut, compteur FROM alerts")[0][:], ("en_cours", 2))
        c.base.fermer()

    def test_evenements_non_alertes_ne_creent_rien(self):
        self.ajouter({"timestamp": "2026-10-26T12:00:00+0000", "event_type": "stats"},
                     {"timestamp": "2026-10-26T12:00:05+0000", "event_type": "flow"})
        c = self.collecteur()
        stats = c.cycle()
        self.assertEqual((stats["lignes"], stats["alertes"]), (2, 0))
        self.assertEqual(self.sql("SELECT dernier_evenement FROM collector_state")[0][0],
                         "2026-10-26T12:00:05Z")
        c.base.fermer()


if __name__ == "__main__":
    unittest.main()
