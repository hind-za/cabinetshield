# API REST CabinetShield, version 1

- Préfixe `/api`, réponses en JSON UTF-8, dates UTC ISO 8601.
- Authentification : en-tête `Authorization: Bearer <jeton>` sur tout sauf `/api/health`.
- Erreurs : `{"erreur": "code_court", "detail": "message lisible"}`.
- Valeurs : gravite = informatif|faible|moyen|eleve, statut = a_examiner|en_cours|traitee.

## GET /api/health  (200, 503)
Sans jeton. 200 si l'API lit la base, sinon 503.

    {"statut": "ok", "version_schema": 1}

## GET /api/alerts  (200, 400, 401)
Paramètres : page (défaut 1), page_size (défaut 20, max 100), gravite, statut,
depuis, jusqua (dates ISO). Tri : derniere_vue décroissant.

    {"page": 1, "page_size": 20, "total": 3,
     "alertes": [
       {"id": 2, "signature": "CABINETSHIELD TEST Tentatives SSH repetees",
        "gravite": "moyen", "statut": "a_examiner", "compteur": 2,
        "src_ip": "192.168.1.45", "dest_ip": "192.168.1.10", "dest_port": 22,
        "premiere_vue": "2026-10-26T12:39:49Z", "derniere_vue": "2026-10-26T12:39:49Z"}
     ]}

## GET /api/alerts/{id}  (200, 401, 404)
Tous les champs de la table alerts, notamment :

    {"id": 2, "gravite": "moyen", "gravite_suricata": 2, "confiance": "elevee",
     "explication": "Un appareil a tenté de nombreuses connexions SSH en peu de temps. Cela peut indiquer une recherche d'accès non autorisé.",
     "action_recommandee": "Vérifiez si cet appareil est légitime.",
     "statut": "a_examiner", "compteur": 2, "...": "..."}

## GET /api/summary  (200, 401)

    {"total": 4, "par_gravite": {"informatif": 1, "faible": 0, "moyen": 2, "eleve": 1},
     "par_statut": {"a_examiner": 4, "en_cours": 0, "traitee": 0},
     "derniere_alerte": "2026-10-26T12:39:49Z"}

## GET /api/sensors/status  (200, 401)
etat : actif | indisponible (dernier_cycle trop ancien) | erreur (erreurs de lecture).

    {"etat": "actif", "dernier_cycle": "2026-10-26T12:45:00Z",
     "dernier_evenement": "2026-10-26T12:39:49Z",
     "erreurs_lecture": 0, "derniere_erreur": null}

## PATCH /api/alerts/{id}/statut  (200, 400, 401, 404)
Corps : {"statut": "en_cours"}. Statut invalide ou corps absent : 400.
Réponse : l'alerte mise à jour. Chaque changement est écrit dans admin_log.
