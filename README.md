# SDP-Tests

Tests de [SDP](https://github.com/LucienLassalle/SDP), lancés par la CI de SDP sur chaque pull request.
Ce dépôt ne contient aucun workflow : c'est SDP qui le récupère et l'exécute contre son propre code.

## Contenu

| Marqueur     | Fichier               | Ce qui est testé                                                        |
|--------------|-----------------------|-------------------------------------------------------------------------|
| `lint`       | `tests/test_lint.py`    | ESLint (`*.js`), hadolint (`Dockerfile`), ShellCheck (`*.sh`) et actionlint (`.github/workflows`) ; configuration dans `lint/` |
| `static`     | `tests/test_trivy.py`   | Trivy sur le code (vulnérabilités, secrets, mauvaises configurations) et sur l'image Docker ; CRITICAL/HIGH bloquants |
| `static`     | `tests/test_compose.py` | KICS sur `docker-compose.yml` (secrets, ports, capabilities...) et Trivy sur chaque image du compose ; CRITICAL/HIGH bloquants |
| `static`     | `tests/test_systemd.py` | `systemd-analyze security` sur `deploy/*.service` : score d'exposition max `SYSTEMD_SECURITY_THRESHOLD` |
| `functional` | `tests/test_app.py`     | Tests de l'application déployée, une classe par fonctionnalité : accueil (`TestHome`), connexion/déconnexion (`TestLogin`), publication (`TestPost`), recherche (`TestSearch`) |
| `functional`, `fuzz` | `tests/test_zap.py` | Fuzzing par [OWASP ZAP](https://www.zaproxy.org/docs/docker/full-scan/) : exploration puis scan actif (injections SQL, XSS, commandes...) ; alertes High bloquantes |

Les linters ne construisent rien et passent en premier. Viennent ensuite les analyses statiques :
si elles échouent, l'application n'est pas déployée.

Les linters sont épinglés comme le reste : hadolint, ShellCheck et actionlint par `requirements.txt`
(binaires publiés sur PyPI), ESLint par `package.json` / `package-lock.json` (Node.js 20.19+, 22.13+ ou 24+).
Dependabot suit les deux. Les règles hadolint ignorées sont justifiées dans `lint/hadolint.yaml`.

La base de SDP démarre vide : les tests fonctionnels créent leurs propres comptes (via `/register`,
identifiants aléatoires) et publient des messages, ils sont donc prévus pour une base jetable, comme celle
de la CI. Ils vérifient aussi que les anciens comptes par défaut (`alice`, `bob`, `charlie`, `admin`)
n'existent plus.

## Lancer en local

```bash
python3 -m pip install -r requirements.txt
npm ci

# 0. Linters (aucun build nécessaire)
SDP_SRC=../SDP pytest -m lint

# 1. Analyses statiques (binaires `trivy` / `kics` si présents, sinon images épinglées dans conftest.py)
docker build -t sdp:local ../SDP
SDP_SRC=../SDP SDP_IMAGE=sdp:local pytest -m static

# 2. Tests fonctionnels sur l'application démarrée
(cd ../SDP && SESSION_SECRET=dev docker compose up -d --wait)
(cd ../SDP && docker compose run --rm --no-deps --entrypoint cat tls /tls/cert.pem) > /tmp/sdp-ca.pem
SDP_URL=https://localhost REQUESTS_CA_BUNDLE=/tmp/sdp-ca.pem pytest -m functional
# Sans le scan ZAP (plusieurs minutes) : -m "functional and not fuzz"
```

ZAP tourne dans son image Docker officielle avec le réseau de l'hôte, pour joindre `SDP_URL` sur localhost.
Son scan actif envoie de vraies requêtes d'attaque : il peut ajouter des données en base, à lancer sur une
instance jetable. En cas d'échec, le message indique le rapport HTML complet.

| Variable              | Défaut                  | Rôle                                  |
|-----------------------|-------------------------|---------------------------------------|
| `SDP_SRC`             | `../SDP`                | Code source analysé par Trivy         |
| `SDP_IMAGE`           | —                       | Image Docker analysée par Trivy       |
| `SDP_URL`             | `http://localhost:3000` | Application testée (`https://localhost` avec SDP actuel) |
| `REQUESTS_CA_BUNDLE`  | —                       | Certificat autosigné de SDP, pour le vérifier |
| `SDP_STARTUP_TIMEOUT` | `120`                   | Attente max (s) du démarrage de l'app |
| `ZAP_FAIL_RISK`       | `high`                  | Risque ZAP bloquant : `high`, `medium` ou `low` |
| `ZAP_MAX_MINUTES`     | `10`                    | Durée max du scan actif ZAP (minutes) |
| `SYSTEMD_SECURITY_THRESHOLD` | `5`              | Score d'exposition systemd max accepté |
| `CONTAINER_ENGINE`    | `docker`                | `docker` ou `podman`, pour lancer Trivy, KICS et ZAP |
| `COMPOSE`             | `$CONTAINER_ENGINE compose` | Commande compose utilisée pour lister les images |
| `IMAGE_TAG`           | `dev`                   | Tag de l'image SDP dans le compose (doit correspondre à `SDP_IMAGE`) |

## Versions

La CI de SDP utilise pour l'instant la branche `main` de ce dépôt. À terme, elle utilisera une release fixe
(tag `vX.Y.Z`) pour que les tests ne changent pas sans une modification explicite dans SDP.
