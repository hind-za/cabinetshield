"""Tests de l'API. Lancement : python3 -m unittest discover -s tests -v"""
import shutil
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE))

from api.app import create_app  # noqa: E402
from collector.collecteur import Collecteur  # noqa: E402

SCHEMA = RACINE / "docs" / "schema.sql"
ECHANTILLON = RACINE / "tests" / "data" / "eve_alerts_sample.json"
JETON = "jeton-de-test-0123456789abcdef"
AUTH = {"Authorization": f"Bearer {JETON}"}


class BaseAPI(unittest.TestCase):
    def setUp(self):
        self.dossier = Path(tempfile.mkdtemp())
        self.db = self.dossier / "t.db"
        eve = self.dossier / "eve.json"
        shutil.copy(ECHANTILLON, eve)
        c = Collecteur(eve, self.db, SCHEMA)       # base réelle, remplie par le vrai collecteur
        c.cycle()
        c.base.fermer()
        self.app = create_app(str(self.db), JETON)
        self.client = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.dossier, ignore_errors=True)

    def sql(self, requete, params=()):
        conn = sqlite3.connect(self.db)
        try:
            return conn.execute(requete, params).fetchall()
        finally:
            conn.close()


class TestAuthentification(BaseAPI):
    def test_health_sans_jeton(self):
        r = self.client.get("/api/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json(), {"statut": "ok", "version_schema": 1})

    def test_routes_protegees_refusent_sans_jeton(self):
        for methode, url in [("get", "/api/alerts"), ("get", "/api/alerts/1"),
                             ("get", "/api/summary"), ("get", "/api/sensors/status"),
                             ("patch", "/api/alerts/1/statut")]:
            r = getattr(self.client, methode)(url)
            self.assertEqual(r.status_code, 401, url)
            self.assertEqual(r.get_json()["erreur"], "non_authentifie")

    def test_mauvais_jeton_et_schema_incorrect(self):
        for entete in ({"Authorization": "Bearer faux"}, {"Authorization": JETON},
                       {"Authorization": f"Basic {JETON}"}, {"Authorization": "Bearer "}):
            self.assertEqual(self.client.get("/api/alerts", headers=entete).status_code, 401)

    def test_refus_journalise_sans_le_jeton(self):
        self.client.get("/api/alerts", headers={"Authorization": "Bearer secret-tente"})
        lignes = self.sql("SELECT action, detail FROM admin_log")
        self.assertEqual(lignes[0][0], "connexion_refusee")
        self.assertNotIn("secret-tente", str(lignes))

    def test_jeton_trop_court_refuse_au_demarrage(self):
        with self.assertRaises(ValueError):
            create_app(str(self.db), "court")


class TestListe(BaseAPI):
    def test_liste_par_defaut(self):
        r = self.client.get("/api/alerts", headers=AUTH)
        j = r.get_json()
        self.assertEqual(r.status_code, 200)
        self.assertEqual((j["page"], j["page_size"], j["total"]), (1, 20, 3))
        self.assertEqual(len(j["alertes"]), 3)
        self.assertEqual(set(j["alertes"][0]),
                         {"id", "signature", "gravite", "statut", "compteur", "src_ip",
                          "dest_ip", "dest_port", "premiere_vue", "derniere_vue"})
        vues = [a["derniere_vue"] for a in j["alertes"]]
        self.assertEqual(vues, sorted(vues, reverse=True))

    def test_filtres(self):
        def total(q):
            return self.client.get("/api/alerts" + q, headers=AUTH).get_json()["total"]
        self.assertEqual(total("?gravite=eleve"), 1)
        self.assertEqual(total("?gravite=faible"), 0)
        self.assertEqual(total("?statut=a_examiner"), 3)
        self.assertEqual(total("?statut=traitee"), 0)
        self.assertEqual(total("?depuis=2026-10-26"), 3)
        self.assertEqual(total("?depuis=2026-10-27"), 0)
        self.assertEqual(total("?jusqua=2026-10-26T16:39:49Z"), 3)
        self.assertEqual(total("?jusqua=2026-10-26T16:39:48Z"), 0)

    def test_pagination(self):
        j = self.client.get("/api/alerts?page_size=2&page=2", headers=AUTH).get_json()
        self.assertEqual((j["total"], len(j["alertes"])), (3, 1))
        j = self.client.get("/api/alerts?page=9", headers=AUTH).get_json()
        self.assertEqual(j["alertes"], [])

    def test_parametres_invalides_400(self):
        for q in ("?page=0", "?page=abc", "?page_size=0", "?page_size=101", "?gravite=critique",
                  "?statut=fini", "?depuis=hier", "?jusqua=2026-13-45"):
            r = self.client.get("/api/alerts" + q, headers=AUTH)
            self.assertEqual(r.status_code, 400, q)
            self.assertEqual(r.get_json()["erreur"], "parametre_invalide")

    def test_injection_sql_neutralisee(self):
        r = self.client.get("/api/alerts?gravite=eleve' OR '1'='1", headers=AUTH)
        self.assertEqual(r.status_code, 400)
        r = self.client.get("/api/alerts?depuis=2026'; DROP TABLE alerts;--", headers=AUTH)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.sql("SELECT COUNT(*) FROM alerts")[0][0], 3)


class TestDetail(BaseAPI):
    def test_detail_200(self):
        j = self.client.get("/api/alerts/2", headers=AUTH).get_json()
        for champ in ("explication", "action_recommandee", "confiance", "gravite_suricata",
                      "cle_dedup", "categorie", "maj_le"):
            self.assertIn(champ, j)
        self.assertEqual((j["gravite"], j["compteur"]), ("moyen", 2))

    def test_detail_404_et_id_non_entier(self):
        r = self.client.get("/api/alerts/999", headers=AUTH)
        self.assertEqual((r.status_code, r.get_json()["erreur"]), (404, "introuvable"))
        self.assertEqual(self.client.get("/api/alerts/abc", headers=AUTH).status_code, 404)


class TestSummaryEtCapteur(BaseAPI):
    def test_summary(self):
        j = self.client.get("/api/summary", headers=AUTH).get_json()
        self.assertEqual(j["total"], 3)  # 4 lignes eve.json -> 3 alertes (SSH dédupliquée)
        self.assertEqual(j["par_gravite"],
                         {"informatif": 1, "faible": 0, "moyen": 1, "eleve": 1})
        self.assertEqual(j["par_statut"], {"a_examiner": 3, "en_cours": 0, "traitee": 0})
        self.assertEqual(j["derniere_alerte"], "2026-10-26T16:39:49Z")

    def test_summary_base_vide(self):
        conn = sqlite3.connect(self.db)
        conn.execute("DELETE FROM alerts")
        conn.commit()
        conn.close()
        j = self.client.get("/api/summary", headers=AUTH).get_json()
        self.assertEqual((j["total"], j["derniere_alerte"]), (0, None))
        self.assertEqual(j["par_gravite"]["eleve"], 0)

    def maj_etat(self, **valeurs):
        conn = sqlite3.connect(self.db)
        for k, v in valeurs.items():
            conn.execute(f"UPDATE collector_state SET {k} = ? WHERE id = 1", (v,))
        conn.commit(); conn.close()

    def test_capteur_actif(self):
        self.maj_etat(erreurs_lecture=0)
        j = self.client.get("/api/sensors/status", headers=AUTH).get_json()
        self.assertEqual(j["etat"], "actif")
        self.assertEqual(set(j), {"etat", "dernier_cycle", "dernier_evenement",
                                  "erreurs_lecture", "derniere_erreur"})

    def test_capteur_indisponible_si_cycle_trop_ancien(self):
        ancien = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.maj_etat(dernier_cycle=ancien)
        self.assertEqual(self.client.get("/api/sensors/status", headers=AUTH).get_json()["etat"],
                         "indisponible")

    def test_capteur_erreur(self):
        self.maj_etat(erreurs_lecture=2, derniere_erreur="ligne ignorée : x")
        j = self.client.get("/api/sensors/status", headers=AUTH).get_json()
        self.assertEqual((j["etat"], j["erreurs_lecture"]), ("erreur", 2))

    def test_capteur_jamais_demarre(self):
        self.maj_etat(dernier_cycle=None)
        self.assertEqual(self.client.get("/api/sensors/status", headers=AUTH).get_json()["etat"],
                         "indisponible")


class TestPatch(BaseAPI):
    def patch(self, url, **kw):
        return self.client.patch(url, headers=AUTH, **kw)

    def test_changement_de_statut_et_journal(self):
        r = self.patch("/api/alerts/3/statut", json={"statut": "en_cours"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["statut"], "en_cours")
        self.assertEqual(self.client.get("/api/alerts/3", headers=AUTH).get_json()["statut"],
                         "en_cours")
        log = self.sql("SELECT action, alerte_id, detail FROM admin_log")
        self.assertEqual(log, [("changement_statut", 3, "a_examiner -> en_cours")])

    def test_statut_invalide_ou_corps_absent_400(self):
        for kw in ({"json": {"statut": "fini"}}, {"json": {"statut": 5}}, {"json": {}},
                   {"json": [1]}, {"data": "pas du json"}, {}):
            r = self.patch("/api/alerts/1/statut", **kw)
            self.assertEqual(r.status_code, 400, kw)
        self.assertEqual(self.sql("SELECT COUNT(*) FROM admin_log")[0][0], 0)
        self.assertEqual(self.sql("SELECT statut FROM alerts WHERE id = 1")[0][0], "a_examiner")

    def test_alerte_inconnue_404(self):
        self.assertEqual(self.patch("/api/alerts/999/statut", json={"statut": "traitee"}).status_code,
                         404)

    def test_methode_non_autorisee(self):
        r = self.client.post("/api/alerts", headers=AUTH)
        self.assertEqual((r.status_code, r.get_json()["erreur"]), (405, "methode_non_autorisee"))


class TestRobustesse(BaseAPI):
    def test_health_503_si_base_illisible(self):
        app = create_app(str(self.dossier / "inexistant" / "x.db"), JETON)
        r = app.test_client().get("/api/health")
        self.assertEqual((r.status_code, r.get_json()["erreur"]), (503, "base_indisponible"))

    def test_erreurs_toujours_en_json(self):
        r = self.client.get("/api/inconnue", headers=AUTH)
        self.assertEqual(r.status_code, 404)
        self.assertEqual(set(r.get_json()), {"erreur", "detail"})

    def test_accents_non_echappes(self):
        brut = self.client.get("/api/alerts/2", headers=AUTH).get_data(as_text=True)
        self.assertIn("tenté", brut)


if __name__ == "__main__":
    unittest.main()
