"""Tests fonctionnels de l'application déployée : chaque page et chaque action du forum."""
import os
import re
import time
import uuid

import pytest
import requests

pytestmark = pytest.mark.functional

STARTUP_TIMEOUT = int(os.environ.get("SDP_STARTUP_TIMEOUT", "120"))
TIMEOUT = 10

# Comptes et messages créés par db/init.sql de SDP
USERS = {"alice": "password1", "bob": "qwerty", "charlie": "letmein"}
SEED_MESSAGES = [  # du plus ancien au plus récent
    ("alice", "Bienvenue sur le forum du TP sécurité !"),
    ("bob", "Quelqu'un a testé la page de recherche ?"),
    ("charlie", "Pensez à bien documenter les failles trouvées."),
]


# --- Fixtures -----------------------------------------------------------------

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


@pytest.fixture
def client(base_url):
    """Navigateur anonyme : garde les cookies et préfixe les chemins par l'URL de l'app."""

    class Client(requests.Session):
        def request(self, method, path, **kwargs):
            kwargs.setdefault("timeout", TIMEOUT)
            kwargs.setdefault("allow_redirects", False)
            return super().request(method, base_url + path, **kwargs)

        def get(self, path, **kwargs):
            # requests.Session.get suit les redirections par défaut : on veut voir les 302
            return self.request("GET", path, **kwargs)

        def csrf_token(self, path="/login"):
            """Jeton CSRF du formulaire de la page, lié au cookie de session."""
            page = self.get(path)
            match = re.search(r'name="_csrf" value="([^"]+)"', page.text)
            assert match, f"aucun jeton CSRF dans {path}"
            return match.group(1)

        def login(self, username="alice", password=None):
            password = USERS[username] if password is None else password
            return self.post("/login", data={"_csrf": self.csrf_token(),
                                             "username": username, "password": password})

        def publish(self, content):
            return self.post("/post", data={"_csrf": self.csrf_token("/"), "content": content})

    with Client() as session:
        yield session


@pytest.fixture
def alice(client):
    """Navigateur connecté avec le compte alice."""
    assert client.login("alice").status_code == 302
    return client


def unique(text="Message de test"):
    """Texte introuvable ailleurs dans la base, pour retrouver ce que le test a publié."""
    return f"{text} {uuid.uuid4().hex}"


def is_logged_in(page, username):
    return f"Connecté : <b>{username}</b>" in page.text and 'href="/logout"' in page.text


# --- Page d'accueil -----------------------------------------------------------

class TestHome:
    def test_is_html_utf8(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert r.headers["Content-Type"].lower() == "text/html; charset=utf-8"
        assert "<h1>Forum</h1>" in r.text

    def test_navigation_when_anonymous(self, client):
        r = client.get("/")
        for link in ('href="/"', 'href="/search"', 'href="/login"'):
            assert link in r.text
        assert 'href="/logout"' not in r.text

    def test_lists_seed_messages(self, client):
        r = client.get("/")
        for author, content in SEED_MESSAGES:
            assert f'<span class="author">{author}</span>' in r.text
            assert content in r.text

    def test_messages_are_newest_first(self, client):
        r = client.get("/")
        positions = [r.text.index(content) for _, content in SEED_MESSAGES]
        assert positions == sorted(positions, reverse=True)

    def test_anonymous_cannot_see_post_form(self, client):
        r = client.get("/")
        assert "Connectez-vous pour publier un message." in r.text
        assert 'action="/post"' not in r.text

    def test_unknown_page_returns_404(self, client):
        assert client.get("/page-inexistante").status_code == 404


# --- Connexion et déconnexion -------------------------------------------------

class TestLogin:
    def test_form(self, client):
        r = client.get("/login")
        assert r.status_code == 200
        assert 'action="/login"' in r.text
        for field in ('name="_csrf"', 'name="username"', 'name="password" type="password"'):
            assert field in r.text

    def test_session_cookie_is_set(self, client):
        # Sans cookie de session reçu (ex. cookie secure servi en HTTP), le jeton CSRF est refusé
        client.get("/login")
        assert "forum.sid" in client.cookies

    @pytest.mark.parametrize("username", USERS)
    def test_valid_credentials(self, client, username):
        r = client.login(username)
        assert r.status_code == 302
        assert r.headers["Location"] == "/"
        assert is_logged_in(client.get("/"), username)

    def test_logged_in_navigation(self, alice):
        r = alice.get("/")
        assert 'href="/login"' not in r.text
        assert 'href="/logout"' in r.text

    def test_wrong_password(self, client):
        r = client.login("alice", "mauvais-mot-de-passe")
        assert r.status_code == 200
        assert "Identifiants invalides." in r.text
        assert not is_logged_in(client.get("/"), "alice")

    def test_unknown_user(self, client):
        r = client.post("/login", data={"_csrf": client.csrf_token(),
                                        "username": "inconnu", "password": "x"})
        assert r.status_code == 200
        assert "Identifiants invalides." in r.text

    def test_without_csrf_is_rejected(self, client):
        r = client.post("/login", data={"username": "alice", "password": USERS["alice"]})
        assert r.status_code == 403

    def test_with_wrong_csrf_is_rejected(self, client):
        client.get("/login")
        r = client.post("/login", data={"_csrf": "faux-jeton", "username": "alice",
                                        "password": USERS["alice"]})
        assert r.status_code == 403
        assert not is_logged_in(client.get("/"), "alice")

    def test_logout(self, alice):
        r = alice.get("/logout")
        assert r.status_code == 302
        assert r.headers["Location"] == "/"
        home = alice.get("/")
        assert not is_logged_in(home, "alice")
        assert 'href="/login"' in home.text


# --- Publication de messages --------------------------------------------------

class TestPost:
    def test_form_when_logged_in(self, alice):
        r = alice.get("/")
        assert 'action="/post"' in r.text
        assert 'name="_csrf"' in r.text
        assert 'name="content"' in r.text
        assert "Connectez-vous pour publier un message." not in r.text

    def test_publish_message(self, alice):
        content = unique()
        r = alice.publish(content)
        assert r.status_code == 302
        assert r.headers["Location"] == "/"

        # Le message est affiché en premier, signé par l'utilisateur connecté
        first = re.search(r'<div class="msg">(.*?)</div>', alice.get("/").text, re.S).group(1)
        assert content in first
        assert '<span class="author">alice</span>' in first

    def test_message_visible_by_anonymous(self, alice, base_url):
        content = unique()
        alice.publish(content)
        assert content in requests.get(base_url + "/", timeout=TIMEOUT).text

    def test_accents_are_kept(self, alice):
        content = unique("Éléphant à côté du garçon, ça marche ?")
        alice.publish(content)
        assert content in alice.get("/").text

    def test_anonymous_is_redirected_to_login(self, client):
        content = unique()
        r = client.post("/post", data={"_csrf": client.csrf_token(), "content": content})
        assert r.status_code == 302
        assert r.headers["Location"] == "/login"
        assert content not in client.get("/").text

    def test_without_csrf_is_rejected(self, alice):
        content = unique()
        r = alice.post("/post", data={"content": content})
        assert r.status_code == 403
        assert content not in alice.get("/").text


# --- Recherche ----------------------------------------------------------------

class TestSearch:
    def test_form_without_query(self, client):
        r = client.get("/search")
        assert r.status_code == 200
        assert "<h1>Recherche</h1>" in r.text
        assert 'name="q"' in r.text
        assert "Aucun résultat." not in r.text
        assert '<div class="msg">' not in r.text

    def test_finds_message(self, client):
        r = client.get("/search", params={"q": "documenter"})
        assert r.status_code == 200
        assert "Pensez à bien documenter les failles trouvées." in r.text
        assert '<span class="author">charlie</span>' in r.text
        # Seul le message correspondant est affiché
        assert "Bienvenue sur le forum" not in r.text

    def test_keeps_query_in_form(self, client):
        r = client.get("/search", params={"q": "documenter"})
        assert 'value="documenter"' in r.text

    def test_is_case_insensitive(self, client):
        r = client.get("/search", params={"q": "DOCUMENTER"})
        assert "Pensez à bien documenter les failles trouvées." in r.text

    def test_with_accents(self, client):
        r = client.get("/search", params={"q": "sécurité"})
        assert "Bienvenue sur le forum du TP sécurité !" in r.text

    def test_no_result(self, client):
        r = client.get("/search", params={"q": unique("introuvable")})
        assert r.status_code == 200
        assert "Aucun résultat." in r.text

    def test_finds_published_message(self, alice):
        content = unique()
        alice.publish(content)
        r = alice.get("/search", params={"q": content.split()[-1]})
        assert content in r.text

    def test_escapes_query(self, client):
        payload = '"><script>alert(1)</script>'
        r = client.get("/search", params={"q": payload})
        assert r.status_code == 200
        assert "<script>alert(1)</script>" not in r.text
