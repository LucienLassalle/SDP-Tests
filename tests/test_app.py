import re
import secrets

import pytest
import requests

pytestmark = pytest.mark.functional


def csrf_token(session, url):
    # Le cookie de session doit être reçu, sinon le jeton CSRF est refusé
    page = session.get(url, timeout=10)
    assert page.status_code == 200
    assert session.cookies, "aucun cookie de session reçu (cookie secure servi en HTTP ?)"
    return re.search(r'name="_csrf" value="([^"]+)"', page.text).group(1)


def register(base_url, username, password, confirm=None):
    session = requests.Session()
    token = csrf_token(session, base_url + "/register")
    r = session.post(base_url + "/register", timeout=10, allow_redirects=False, data={
        "_csrf": token, "username": username, "password": password,
        "confirm": password if confirm is None else confirm,
    })
    return session, r


def login(base_url, username, password):
    session = requests.Session()
    token = csrf_token(session, base_url + "/login")
    r = session.post(base_url + "/login", timeout=10, allow_redirects=False,
                     data={"_csrf": token, "username": username, "password": password})
    return session, r


def post_message(base_url, session, content):
    token = csrf_token(session, base_url + "/")
    r = session.post(base_url + "/post", data={"_csrf": token, "content": content},
                     allow_redirects=False, timeout=10)
    assert r.status_code == 302


@pytest.fixture
def account(base_url):
    """Compte neuf et connecté : (session, identifiant, mot de passe)."""
    username = "test_" + secrets.token_hex(6)
    password = secrets.token_urlsafe(16)
    session, r = register(base_url, username, password)
    assert r.status_code == 302, r.text
    return session, username, password


def test_home_page(base_url):
    r = requests.get(base_url + "/", timeout=10)
    assert r.status_code == 200
    assert "<h1>Forum</h1>" in r.text
    assert 'href="/register"' in r.text


def test_login_form_has_csrf_token(base_url):
    r = requests.get(base_url + "/login", timeout=10)
    assert r.status_code == 200
    assert 'name="_csrf"' in r.text


def test_login_without_csrf_is_rejected(base_url):
    r = requests.post(base_url + "/login", data={"username": "admin", "password": "x"},
                      allow_redirects=False, timeout=10)
    assert r.status_code == 403


def test_register_logs_in(base_url, account):
    session, username, _ = account
    home = session.get(base_url + "/", timeout=10)
    assert f"Connecté : <b>{username}</b>" in home.text


def test_login_with_registered_account(base_url, account):
    _, username, password = account
    session, r = login(base_url, username, password)
    assert r.status_code == 302
    assert f"Connecté : <b>{username}</b>" in session.get(base_url + "/", timeout=10).text


def test_login_with_wrong_password_is_rejected(base_url, account):
    _, username, _ = account
    _, r = login(base_url, username, "mauvais mot de passe")
    assert r.status_code == 200
    assert "Identifiants invalides" in r.text


def test_login_is_not_injectable(base_url, account):
    _, username, _ = account
    for payload in (f"{username}' -- ", "' OR '1'='1' -- "):
        _, r = login(base_url, payload, "x")
        assert r.status_code == 200
        assert "Identifiants invalides" in r.text


def test_register_rejects_duplicate_username(base_url, account):
    _, username, _ = account
    _, r = register(base_url, username, secrets.token_urlsafe(16))
    assert r.status_code == 409


@pytest.mark.parametrize("username, password, confirm", [
    ("ab", "un mot de passe assez long", None),                               # identifiant trop court
    ("bad<name>", "un mot de passe assez long", None),                        # caractère interdit
    ("test_" + secrets.token_hex(6), "court", None),                          # mot de passe trop court
    ("test_" + secrets.token_hex(6), "un mot de passe assez long", "autre"),  # confirmation différente
])
def test_register_rejects_invalid_input(base_url, username, password, confirm):
    _, r = register(base_url, username, password, confirm)
    assert r.status_code == 400
    assert "Identifiants invalides" in login(base_url, username, password)[1].text


def test_password_page_requires_login(base_url):
    r = requests.get(base_url + "/password", allow_redirects=False, timeout=10)
    assert r.status_code == 302
    assert r.headers["Location"] == "/login"


def test_change_password(base_url, account):
    session, username, password = account
    new_password = secrets.token_urlsafe(16)
    token = csrf_token(session, base_url + "/password")
    r = session.post(base_url + "/password", timeout=10, data={
        "_csrf": token, "current": password, "password": new_password, "confirm": new_password,
    })
    assert r.status_code == 200
    assert "Mot de passe modifié" in r.text
    assert "Identifiants invalides" in login(base_url, username, password)[1].text
    assert login(base_url, username, new_password)[1].status_code == 302


def test_change_password_requires_current_password(base_url, account):
    session, username, password = account
    token = csrf_token(session, base_url + "/password")
    r = session.post(base_url + "/password", timeout=10, data={
        "_csrf": token, "current": "mauvais mot de passe",
        "password": "nouveau mot de passe", "confirm": "nouveau mot de passe",
    })
    assert r.status_code == 403
    assert login(base_url, username, password)[1].status_code == 302


def test_search_finds_message(base_url, account):
    session, _, _ = account
    marker = secrets.token_hex(8)
    post_message(base_url, session, f"Pensez à bien documenter {marker}")
    r = requests.get(base_url + "/search", params={"q": marker}, timeout=10)
    assert r.status_code == 200
    assert f"Pensez à bien documenter {marker}" in r.text


def test_search_wildcards_are_literal(base_url, account):
    session, _, _ = account
    marker = secrets.token_hex(8)
    post_message(base_url, session, marker)
    r = requests.get(base_url + "/search", params={"q": marker[:4] + "%" + marker[-4:]}, timeout=10)
    assert r.status_code == 200
    assert marker not in r.text


def test_accents_are_displayed(base_url, account):
    session, _, _ = account
    post_message(base_url, session, "Bienvenue sur le forum du TP sécurité !")
    r = requests.get(base_url + "/", timeout=10)
    assert r.status_code == 200
    assert "Bienvenue sur le forum du TP sécurité" in r.text


def test_messages_are_escaped(base_url, account):
    session, _, _ = account
    post_message(base_url, session, "<script>alert(1)</script>")
    r = requests.get(base_url + "/", timeout=10)
    assert "<script>alert(1)</script>" not in r.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in r.text


def test_search_escapes_query(base_url):
    payload = '"><script>alert(1)</script>'
    r = requests.get(base_url + "/search", params={"q": payload}, timeout=10)
    assert r.status_code == 200
    assert "<script>alert(1)</script>" not in r.text
