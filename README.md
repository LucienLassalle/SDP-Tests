# SDP-Tests

Tests de [SDP](https://github.com/LucienLassalle/SDP), lancés par la CI de SDP sur chaque pull request.
Ce dépôt ne contient aucun workflow : c'est SDP qui le récupère et l'exécute contre son propre code.

## Contenu

| Marqueur     | Fichier               | Ce qui est testé                                                        |
|--------------|-----------------------|-------------------------------------------------------------------------|
| `static`     | `tests/test_trivy.py`   | Trivy sur le code (vulnérabilités, secrets, mauvaises configurations) et sur l'image Docker ; CRITICAL/HIGH bloquants |
| `static`     | `tests/test_compose.py` | KICS sur `docker-compose.yml` (secrets, ports, capabilities...) et Trivy sur chaque image du compose ; CRITICAL/HIGH bloquants |
| `static`     | `tests/test_systemd.py` | `systemd-analyze security` sur `deploy/*.service` : score d'exposition max `SYSTEMD_SECURITY_THRESHOLD` |
| `functional` | `tests/test_app.py`     | Tests de l'application déployée (pages, connexion avec jeton CSRF, recherche, échappement, accents) |

Les analyses statiques passent en premier : si elles échouent, l'application n'est pas déployée.

## Lancer en local

```bash
python3 -m pip install -r requirements.txt

# 1. Analyses statiques (binaires `trivy` / `kics` si présents, sinon images épinglées dans conftest.py)
docker build -t sdp:local ../SDP
SDP_SRC=../SDP SDP_IMAGE=sdp:local pytest -m static

# 2. Tests fonctionnels sur l'application démarrée
(cd ../SDP && SESSION_SECRET=dev docker compose up -d --wait)
(cd ../SDP && docker compose run --rm --no-deps --entrypoint cat tls /tls/cert.pem) > /tmp/sdp-ca.pem
SDP_URL=https://localhost REQUESTS_CA_BUNDLE=/tmp/sdp-ca.pem pytest -m functional
```

| Variable              | Défaut                  | Rôle                                  |
|-----------------------|-------------------------|---------------------------------------|
| `SDP_SRC`             | `../SDP`                | Code source analysé par Trivy         |
| `SDP_IMAGE`           | —                       | Image Docker analysée par Trivy       |
| `SDP_URL`             | `http://localhost:3000` | Application testée (`https://localhost` avec SDP actuel) |
| `REQUESTS_CA_BUNDLE`  | —                       | Certificat autosigné de SDP, pour le vérifier |
| `SDP_STARTUP_TIMEOUT` | `120`                   | Attente max (s) du démarrage de l'app |
| `SYSTEMD_SECURITY_THRESHOLD` | `5`              | Score d'exposition systemd max accepté |
| `CONTAINER_ENGINE`    | `docker`                | `docker` ou `podman`, pour lancer Trivy et KICS |
| `COMPOSE`             | `$CONTAINER_ENGINE compose` | Commande compose utilisée pour lister les images |
| `IMAGE_TAG`           | `dev`                   | Tag de l'image SDP dans le compose (doit correspondre à `SDP_IMAGE`) |

## Versions

La CI de SDP utilise pour l'instant la branche `main` de ce dépôt. À terme, elle utilisera une release fixe
(tag `vX.Y.Z`) pour que les tests ne changent pas sans une modification explicite dans SDP.
