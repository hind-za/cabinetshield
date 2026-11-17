"""Normalisation d'un événement EVE JSON en alerte CabinetShield.

Règles d'attribution : voir docs/gravites.md (ordre de priorité 1 à 4).
"""
from datetime import datetime, timezone

from . import explications as ex


class ErreurEvenement(ValueError):
    """Événement inutilisable (JSON invalide, champ obligatoire absent ou mal typé)."""


def vers_utc(horodatage):
    """'2026-10-26T12:39:49.746229-0400' -> '2026-10-26T16:39:49Z'."""
    if not isinstance(horodatage, str) or not horodatage:
        raise ErreurEvenement("timestamp absent ou invalide")
    try:
        dt = datetime.fromisoformat(horodatage)
    except ValueError as e:
        raise ErreurEvenement(f"timestamp illisible : {horodatage!r}") from e
    if dt.tzinfo is None:  # sans fuseau : on suppose UTC
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _entier(valeur):
    """Entier ou None (les ports et sid absents ne doivent pas faire planter)."""
    if isinstance(valeur, bool):
        return None
    try:
        return int(valeur)
    except (TypeError, ValueError):
        return None


def _texte(valeur):
    return valeur if isinstance(valeur, str) and valeur else None


def attribuer_gravite(signature_id, categorie, severite):
    """Retourne (gravite, confiance, explication, action) selon docs/gravites.md."""
    # 1. Dictionnaire par signature_id : impose la gravité, confiance élevée.
    entree = ex.PAR_SIGNATURE.get(signature_id)
    if entree:
        return entree["gravite"], "elevee", entree["explication"], entree["action"]

    cat = ex.PAR_CATEGORIE.get(categorie)

    # 2. Catégorie « not-suspicious » -> informatif.
    if cat and cat.get("gravite") == "informatif":
        return "informatif", "moyenne", cat["explication"], cat["action"]

    # 3. Gravité Suricata (3 -> faible, 2 -> moyen, 1 -> eleve).
    gravite = ex.PAR_SEVERITE_SURICATA.get(severite)
    if gravite:
        if cat:
            return gravite, "moyenne", cat["explication"], cat["action"]
        return gravite, "faible", ex.GENERIQUE_EXPLICATION, ex.GENERIQUE_ACTION

    # 4. Sinon : moyen, confiance faible.
    return "moyen", "faible", ex.GENERIQUE_EXPLICATION, ex.GENERIQUE_ACTION


def cle_dedup(signature_id, src_ip, dest_ip, dest_port):
    """signature_id|src_ip|dest_ip|dest_port (le port source n'en fait pas partie)."""
    return "|".join(
        "" if v is None else str(v)
        for v in (signature_id if signature_id is not None else "sans-sid",
                  src_ip, dest_ip, dest_port)
    )


def normaliser(evenement):
    """Transforme un événement EVE (dict) en dictionnaire prêt pour la table alerts.

    Retourne (horodatage_utc, alerte) ; alerte vaut None si ce n'est pas une alerte.
    Lève ErreurEvenement si l'événement est inutilisable.
    """
    if not isinstance(evenement, dict):
        raise ErreurEvenement("l'événement n'est pas un objet JSON")

    horodatage = vers_utc(evenement.get("timestamp"))

    if evenement.get("event_type") != "alert":
        return horodatage, None

    bloc = evenement.get("alert")
    if not isinstance(bloc, dict):
        raise ErreurEvenement("événement alert sans bloc 'alert'")

    signature_id = _entier(bloc.get("signature_id"))
    signature = _texte(bloc.get("signature")) or "Signature inconnue"
    categorie = _texte(bloc.get("category"))
    severite = _entier(bloc.get("severity"))
    if severite is not None and not 1 <= severite <= 3:
        severite = None  # hors échelle : traité comme absent (contrainte CHECK de la base)

    src_ip = _texte(evenement.get("src_ip"))
    dest_ip = _texte(evenement.get("dest_ip"))
    src_port = _entier(evenement.get("src_port"))
    dest_port = _entier(evenement.get("dest_port"))

    gravite, confiance, explication, action = attribuer_gravite(
        signature_id, categorie, severite
    )

    return horodatage, {
        "cle_dedup": cle_dedup(signature_id, src_ip, dest_ip, dest_port),
        "signature": signature,
        "signature_id": signature_id,
        "categorie": categorie,
        "proto": _texte(evenement.get("proto")),
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "gravite_suricata": severite,
        "gravite": gravite,
        "confiance": confiance,
        "explication": explication,
        "action_recommandee": action,
        "horodatage": horodatage,
    }
