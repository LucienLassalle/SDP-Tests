import os
import re
import time

import pytest
import requests

pytestmark = pytest.mark.functional

STARTUP_TIMEOUT = int(os.environ.get("SDP_STARTUP_TIMEOUT", "120"))


@pytest.fixture(scope="module")
def base_url():
    """URL de l'application, attendue jusqu'à ce que la page d'accueil (et donc la BDD) réponde."""
    url = os.environ.get("SDP_URL", "http://localhost:3000").rstrip("/")
    deadline = time.monotonic() + STARTUP_TIMEOUT
    last = None
    while time.monotonic() < deadline:
        try:
            last = requests.get(url + "/", timeout=5)
            if last.status_code == 200:
                return url
        except requests.RequestException as exc:
            last = exc
        time.sleep(2)
    pytest.fail(f"{url} ne répond pas après {STARTUP_TIMEOUT}s : {last}")


def test_home_lists_messages(base_url):
    r = requests.get(base_url + "/", timeout=10)
    assert r.status_code == 200
    assert "<h1>Forum</h1>" in r.text
    assert "Bienvenue sur le forum" in r.text


def test_login_form_has_csrf_token(base_url):
    r = requests.get(base_url + "/login", timeout=10)
    assert r.status_code == 200
    assert 'name="_csrf"' in r.text


def test_login_without_csrf_is_rejected(base_url):
    r = requests.post(base_url + "/login", data={"username": "alice", "password": "password1"},
                      allow_redirects=False, timeout=10)
    assert r.status_code == 403



def test_login_with_csrf_token(base_url):
    # Parcours complet : le cookie de session doit être reçu, sinon le jeton CSRF est refusé
    session = requests.Session()
    page = session.get(base_url + "/login", timeout=10)
    assert page.status_code == 200
    assert session.cookies, "aucun cookie de session reçu (cookie secure servi en HTTP ?)"
    token = re.search(r'name="_csrf" value="([^"]+)"', page.text).group(1)

    r = session.post(base_url + "/login", timeout=10, allow_redirects=False,
                     data={"_csrf": token, "username": "alice", "password": "password1"})
    assert r.status_code == 302

    home = session.get(base_url + "/", timeout=10)
    assert "Connecté : <b>alice</b>" in home.text

def test_search_finds_message(base_url):
    r = requests.get(base_url + "/search", params={"q": "documenter"}, timeout=10)
    assert r.status_code == 200
    assert "bien documenter les failles" in r.text


def test_accents_are_displayed(base_url):
    r = requests.get(base_url + "/", timeout=10)
    assert r.status_code == 200
    assert "Bienvenue sur le forum du TP sécurité" in r.text


def test_search_escapes_query(base_url):
    payload = '"><script>alert(1)</script>'
    r = requests.get(base_url + "/search", params={"q": payload}, timeout=10)
    assert r.status_code == 200
    assert "<script>alert(1)</script>" not in r.text
