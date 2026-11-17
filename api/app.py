"""API REST CabinetShield, version 1 (voir docs/api.md).

Sécurité :
- jeton obligatoire (Authorization: Bearer ...) sur tout sauf /api/health, comparé en temps constant ;
- requêtes SQL toujours paramétrées (aucune valeur du client n'est concaténée dans le SQL) ;
- messages d'erreur sobres : jamais de trace Python ni de chemin renvoyé au client ;
- le jeton n'est jamais écrit dans les logs ni dans admin_log.
"""
import hmac
import sqlite3
from datetime import datetime, timedelta, timezone

from flask import Flask, g, jsonify, request
from werkzeug.exceptions import HTTPException

VERSION_SCHEMA = 1
GRAVITES = ("informatif", "faible", "moyen", "eleve")
STATUTS = ("a_examiner", "en_cours", "traitee")
PAGE_SIZE_DEFAUT, PAGE_SIZE_MAX = 20, 100
CHAMPS_LISTE = ("id", "signature", "gravite", "statut", "compteur", "src_ip", "dest_ip",
                "dest_port", "premiere_vue", "derniere_vue")


def maintenant_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ErreurAPI(Exception):
    def __init__(self, code_http, erreur, detail):
        self.code_http, self.erreur, self.detail = code_http, erreur, detail


def date_vers_utc(texte, nom):
    """'2026-10-26' ou '2026-10-26T12:00:00Z' -> '2026-10-26T12:00:00Z' (UTC)."""
    try:
        dt = datetime.fromisoformat(texte.replace("Z", "+00:00"))
    except ValueError:
        raise ErreurAPI(400, "parametre_invalide",
                        f"'{nom}' doit être une date ISO 8601 (ex. 2026-10-26T12:00:00Z)")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def entier_borne(texte, nom, defaut, minimum, maximum):
    if texte is None:
        return defaut
    try:
        n = int(texte)
    except ValueError:
        raise ErreurAPI(400, "parametre_invalide", f"'{nom}' doit être un entier")
    if not minimum <= n <= maximum:
        raise ErreurAPI(400, "parametre_invalide",
                        f"'{nom}' doit être compris entre {minimum} et {maximum}")
    return n


def create_app(chemin_db, jeton, delai_indisponible=30):
    """delai_indisponible : secondes sans signal de vie du collecteur avant « indisponible »."""
    if not jeton or len(jeton) < 16:
        raise ValueError("jeton absent ou trop court (16 caractères minimum)")
    jeton_octets = jeton.encode("utf-8")

    app = Flask(__name__)
    app.json.ensure_ascii = False       # accents lisibles dans le JSON
    app.json.sort_keys = False

    # --- base de données : une connexion par requête --------------------
    def db():
        if "db" not in g:
            conn = sqlite3.connect(chemin_db, timeout=10)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            g.db = conn
        return g.db

    @app.teardown_appcontext
    def fermer(_exc):
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    def journaliser(action, alerte_id=None, detail=None):
        db().execute(
            "INSERT INTO admin_log (horodatage, action, alerte_id, detail) VALUES (?,?,?,?)",
            (maintenant_utc(), action, alerte_id, detail),
        )
        db().commit()

    # --- authentification ------------------------------------------------
    @app.before_request
    def verifier_jeton():
        if request.endpoint == "health" or request.endpoint is None:
            return None
        entete = request.headers.get("Authorization", "")
        schema, _, valeur = entete.partition(" ")
        if schema.lower() == "bearer" and hmac.compare_digest(valeur.strip().encode("utf-8"),
                                                              jeton_octets):
            return None
        try:
            journaliser("connexion_refusee", None, f"{request.method} {request.path}")
        except sqlite3.Error:
            pass
        raise ErreurAPI(401, "non_authentifie", "Jeton absent ou invalide.")

    # --- erreurs : toujours {"erreur", "detail"} --------------------------
    @app.errorhandler(ErreurAPI)
    def erreur_api(e):
        rep = jsonify({"erreur": e.erreur, "detail": e.detail})
        rep.status_code = e.code_http
        if e.code_http == 401:
            rep.headers["WWW-Authenticate"] = "Bearer"
        return rep

    @app.errorhandler(404)
    def non_trouve(_e):
        return jsonify({"erreur": "introuvable", "detail": "Ressource inconnue."}), 404

    @app.errorhandler(405)
    def methode(_e):
        return jsonify({"erreur": "methode_non_autorisee", "detail": "Méthode non autorisée."}), 405

    @app.errorhandler(sqlite3.Error)
    def erreur_base(_e):
        return jsonify({"erreur": "base_indisponible",
                        "detail": "La base de données est momentanément indisponible."}), 503

    @app.errorhandler(Exception)
    def erreur_interne(e):
        if isinstance(e, HTTPException):                       # 400, 413, 415... : pas une panne
            return jsonify({"erreur": "requete_invalide", "detail": e.name}), e.code
        app.logger.exception("erreur interne")
        return jsonify({"erreur": "erreur_interne", "detail": "Erreur interne."}), 500

    # --- routes -------------------------------------------------------------
    @app.get("/api/health")
    def health():
        try:
            version = db().execute("SELECT MAX(version) FROM schema_meta").fetchone()[0]
        except sqlite3.Error:
            return jsonify({"erreur": "base_indisponible",
                            "detail": "L'API ne peut pas lire la base."}), 503
        return jsonify({"statut": "ok", "version_schema": version})

    @app.get("/api/alerts")
    def liste_alertes():
        a = request.args
        page = entier_borne(a.get("page"), "page", 1, 1, 10**9)
        taille = entier_borne(a.get("page_size"), "page_size", PAGE_SIZE_DEFAUT, 1, PAGE_SIZE_MAX)
        conditions, params = [], []
        if a.get("gravite") is not None:
            if a["gravite"] not in GRAVITES:
                raise ErreurAPI(400, "parametre_invalide",
                                "'gravite' doit valoir " + "|".join(GRAVITES))
            conditions.append("gravite = ?")
            params.append(a["gravite"])
        if a.get("statut") is not None:
            if a["statut"] not in STATUTS:
                raise ErreurAPI(400, "parametre_invalide",
                                "'statut' doit valoir " + "|".join(STATUTS))
            conditions.append("statut = ?")
            params.append(a["statut"])
        if a.get("depuis") is not None:
            conditions.append("derniere_vue >= ?")
            params.append(date_vers_utc(a["depuis"], "depuis"))
        if a.get("jusqua") is not None:
            conditions.append("derniere_vue <= ?")
            params.append(date_vers_utc(a["jusqua"], "jusqua"))
        # Les fragments SQL ci-dessus sont des constantes ; les valeurs passent par « ? ».
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        total = db().execute(f"SELECT COUNT(*) FROM alerts{where}", params).fetchone()[0]
        lignes = db().execute(
            f"SELECT {', '.join(CHAMPS_LISTE)} FROM alerts{where} "
            "ORDER BY derniere_vue DESC, id DESC LIMIT ? OFFSET ?",
            params + [taille, (page - 1) * taille],
        ).fetchall()
        return jsonify({"page": page, "page_size": taille, "total": total,
                        "alertes": [dict(r) for r in lignes]})

    def alerte_complete(alerte_id):
        ligne = db().execute("SELECT * FROM alerts WHERE id = ?", (alerte_id,)).fetchone()
        if ligne is None:
            raise ErreurAPI(404, "introuvable", f"Alerte {alerte_id} inconnue.")
        return dict(ligne)

    @app.get("/api/alerts/<int:alerte_id>")
    def detail_alerte(alerte_id):
        return jsonify(alerte_complete(alerte_id))

    @app.get("/api/summary")
    def summary():
        par_gravite = dict.fromkeys(GRAVITES, 0)
        par_statut = dict.fromkeys(STATUTS, 0)
        for r in db().execute("SELECT gravite, COUNT(*) AS n FROM alerts GROUP BY gravite"):
            par_gravite[r["gravite"]] = r["n"]
        for r in db().execute("SELECT statut, COUNT(*) AS n FROM alerts GROUP BY statut"):
            par_statut[r["statut"]] = r["n"]
        total, derniere = db().execute("SELECT COUNT(*), MAX(derniere_vue) FROM alerts").fetchone()
        return jsonify({"total": total, "par_gravite": par_gravite, "par_statut": par_statut,
                        "derniere_alerte": derniere})

    @app.get("/api/sensors/status")
    def sensors_status():
        e = db().execute("SELECT * FROM collector_state WHERE id = 1").fetchone()
        if e is None:
            etat, cycle, evt, nb, derniere = "indisponible", None, None, 0, None
        else:
            cycle, evt = e["dernier_cycle"], e["dernier_evenement"]
            nb, derniere = e["erreurs_lecture"], e["derniere_erreur"]
            vivant = False
            if cycle:
                age = datetime.now(timezone.utc) - datetime.strptime(
                    cycle, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                vivant = age <= timedelta(seconds=delai_indisponible)
            etat = "indisponible" if not vivant else ("erreur" if nb > 0 else "actif")
        return jsonify({"etat": etat, "dernier_cycle": cycle, "dernier_evenement": evt,
                        "erreurs_lecture": nb, "derniere_erreur": derniere})

    @app.patch("/api/alerts/<int:alerte_id>/statut")
    def changer_statut(alerte_id):
        corps = request.get_json(silent=True)
        if not isinstance(corps, dict) or "statut" not in corps:
            raise ErreurAPI(400, "corps_invalide", 'Corps JSON attendu : {"statut": "..."}')
        nouveau = corps["statut"]
        if not isinstance(nouveau, str) or nouveau not in STATUTS:
            raise ErreurAPI(400, "statut_invalide", "'statut' doit valoir " + "|".join(STATUTS))
        ancien = alerte_complete(alerte_id)["statut"]          # 404 si inconnue
        db().execute("UPDATE alerts SET statut = ?, maj_le = ? WHERE id = ?",
                     (nouveau, maintenant_utc(), alerte_id))
        db().execute(
            "INSERT INTO admin_log (horodatage, action, alerte_id, detail) VALUES (?,?,?,?)",
            (maintenant_utc(), "changement_statut", alerte_id, f"{ancien} -> {nouveau}"),
        )
        db().commit()                                           # statut + journal ensemble
        return jsonify(alerte_complete(alerte_id))

    return app
