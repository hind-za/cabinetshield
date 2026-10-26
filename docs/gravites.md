# Gravités CabinetShield

Une alerte est un **signal à vérifier**, jamais la preuve d'une compromission.

| Gravité CabinetShield | Signification | Couleur UI |
|---|---|---|
| informatif | Événement normal ou sans risque, à titre d'information | gris |
| faible | Comportement inhabituel, à surveiller | jaune |
| moyen | Comportement suspect, à vérifier dans la journée | orange |
| eleve | Comportement très suspect, à vérifier rapidement | rouge |

## Règles d'attribution (ordre de priorité)
1. Dictionnaire d'explications : une entrée par `signature_id` impose la gravité.
2. Sinon, selon la catégorie (`classtype`) : `not-suspicious` → informatif.
3. Sinon, selon la gravité Suricata : 3 → faible, 2 → moyen, 1 → eleve
   (attention : chez Suricata, 1 est la gravité la plus forte).
4. Sinon : moyen, avec une confiance « faible ».

## Confiance
- elevee : signature_id présent dans le dictionnaire.
- moyenne : catégorie connue seulement.
- faible : ni l'un ni l'autre (explication générique).

## Alertes de test
| sid | Message | Gravité CabinetShield |
|---|---|---|
| 1000001 | Ping informatif | informatif |
| 1000002 | Tentatives SSH répétées | moyen |
| 1000003 | Connexion sortante suspecte | eleve |

## Déduplication
Clé : `signature_id|src_ip|dest_ip|dest_port` (le port source change à chaque
connexion, il n'est pas dans la clé). Une répétition incrémente `compteur` et met
à jour `derniere_vue`.
Point à valider à deux : si l'alerte était « traitee » et revient, repasse-t-elle
à « a_examiner » ? (proposition : oui, et on l'écrit dans admin_log).
