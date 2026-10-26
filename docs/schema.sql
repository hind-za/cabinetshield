-- CabinetShield : schéma SQLite, version 1
-- Dates en UTC, format ISO 8601 (ex. 2026-10-26T12:39:49Z)
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    version     INTEGER NOT NULL,
    applied_at  TEXT NOT NULL
);
INSERT INTO schema_meta (version, applied_at)
SELECT 1, strftime('%Y-%m-%dT%H:%M:%SZ','now')
WHERE NOT EXISTS (SELECT 1 FROM schema_meta);

CREATE TABLE IF NOT EXISTS alerts (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    cle_dedup          TEXT NOT NULL UNIQUE,  -- signature_id|src_ip|dest_ip|dest_port
    premiere_vue       TEXT NOT NULL,
    derniere_vue       TEXT NOT NULL,
    compteur           INTEGER NOT NULL DEFAULT 1 CHECK (compteur >= 1),
    signature          TEXT NOT NULL,
    signature_id       INTEGER,
    categorie          TEXT,
    proto              TEXT,
    src_ip             TEXT,
    src_port           INTEGER,
    dest_ip            TEXT,
    dest_port          INTEGER,
    gravite_suricata   INTEGER CHECK (gravite_suricata BETWEEN 1 AND 3),
    gravite            TEXT NOT NULL CHECK (gravite IN ('informatif','faible','moyen','eleve')),
    confiance          TEXT NOT NULL CHECK (confiance IN ('faible','moyenne','elevee')),
    explication        TEXT NOT NULL,
    action_recommandee TEXT NOT NULL,
    statut             TEXT NOT NULL DEFAULT 'a_examiner'
                       CHECK (statut IN ('a_examiner','en_cours','traitee')),
    maj_le             TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_derniere_vue ON alerts (derniere_vue);
CREATE INDEX IF NOT EXISTS idx_alerts_gravite ON alerts (gravite);
CREATE INDEX IF NOT EXISTS idx_alerts_statut ON alerts (statut);

-- Une seule ligne (id = 1) : position de lecture et santé du collecteur
CREATE TABLE IF NOT EXISTS collector_state (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    fichier_inode     INTEGER,
    offset_octets     INTEGER NOT NULL DEFAULT 0,
    dernier_cycle     TEXT,     -- dernier passage du collecteur (signal de vie)
    dernier_evenement TEXT,     -- dernier événement lu dans eve.json
    erreurs_lecture   INTEGER NOT NULL DEFAULT 0,
    derniere_erreur   TEXT
);
INSERT OR IGNORE INTO collector_state (id) VALUES (1);

CREATE TABLE IF NOT EXISTS admin_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    horodatage TEXT NOT NULL,
    action     TEXT NOT NULL,   -- ex. changement_statut, purge, connexion_refusee
    alerte_id  INTEGER,
    detail     TEXT
);
