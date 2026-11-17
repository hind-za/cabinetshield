"""Dictionnaires d'explications en français (déterministes).

Principe : une alerte est un signal à vérifier, jamais la preuve d'une compromission.
Les textes ci-dessous ne doivent donc jamais affirmer qu'une attaque est prouvée.
"""

# Niveau 1 : une entrée par signature_id. Impose la gravité (confiance « elevee »).
# Les textes des sid 1000001 et 1000003 sont à relire et valider à deux.
PAR_SIGNATURE = {
    1000001: {
        "gravite": "informatif",
        "explication": (
            "Un appareil a envoyé un ping (test de présence) vers un autre appareil "
            "du réseau. C'est un comportement courant, sans danger en général."
        ),
        "action": "Aucune action nécessaire, sauf si ces pings sont très nombreux.",
    },
    1000002: {
        "gravite": "moyen",
        "explication": (
            "Un appareil a tenté de nombreuses connexions SSH en peu de temps. "
            "Cela peut indiquer une recherche d'accès non autorisé."
        ),
        "action": "Vérifiez si cet appareil est légitime.",
    },
    1000003: {
        "gravite": "eleve",
        "explication": (
            "Un appareil du réseau a tenté de se connecter vers l'extérieur sur un "
            "port parfois utilisé par des outils de contrôle à distance. Cela peut "
            "indiquer un poste compromis, mais ce n'est pas une preuve."
        ),
        "action": (
            "Identifiez cet appareil et vérifiez rapidement ce qu'il fait ; "
            "en cas de doute, déconnectez-le du réseau."
        ),
    },
}

# Niveau 2 : catégories Suricata connues (champ alert.category d'eve.json).
# « informatif » impose la gravité ; pour les autres, la gravité vient de Suricata.
PAR_CATEGORIE = {
    "Not Suspicious Traffic": {
        "gravite": "informatif",
        "explication": "Suricata a repéré un trafic classé comme normal ou sans risque.",
        "action": "Aucune action nécessaire.",
    },
    "Attempted Information Leak": {
        "explication": (
            "Un appareil a cherché à obtenir des informations sur le réseau. "
            "Cela peut précéder une tentative d'intrusion, sans que ce soit prouvé."
        ),
        "action": "Vérifiez si cet appareil est légitime.",
    },
    "Attempted Reconnaissance": {
        "explication": (
            "Un appareil a exploré le réseau (recherche de services ouverts). "
            "Cela peut être un outil d'inventaire légitime ou un repérage."
        ),
        "action": "Vérifiez si cet appareil est légitime.",
    },
    "Detection of a Network Scan": {
        "explication": "Un appareil a balayé plusieurs adresses ou ports du réseau.",
        "action": "Vérifiez si un outil d'inventaire est en cours d'utilisation.",
    },
    "A Network Trojan was detected": {
        "explication": (
            "Le trafic ressemble à celui d'un logiciel malveillant connu. "
            "Cela peut aussi être un faux positif."
        ),
        "action": "Identifiez l'appareil concerné et faites-le vérifier rapidement.",
    },
    "Potentially Bad Traffic": {
        "explication": "Suricata a repéré un trafic potentiellement indésirable.",
        "action": "Surveillez : à vérifier si l'alerte se répète.",
    },
    "Attempted Administrator Privilege Gain": {
        "explication": "Une tentative d'obtenir des droits d'administrateur a été signalée.",
        "action": "Faites vérifier l'appareil visé par la personne en charge du réseau.",
    },
    "Web Application Attack": {
        "explication": "Une requête ressemblant à une attaque contre un site ou une application a été signalée.",
        "action": "Faites vérifier l'application visée.",
    },
}

# Niveau 3 : texte générique (confiance « faible »).
GENERIQUE_EXPLICATION = (
    "Suricata a signalé une activité inhabituelle sur le réseau. "
    "Cela ne prouve pas une compromission."
)
GENERIQUE_ACTION = (
    "Notez l'appareil concerné et demandez à la personne en charge de "
    "l'informatique de vérifier si l'alerte se répète."
)

# Gravité Suricata -> gravité CabinetShield (attention : 1 = la plus forte chez Suricata).
PAR_SEVERITE_SURICATA = {3: "faible", 2: "moyen", 1: "eleve"}
