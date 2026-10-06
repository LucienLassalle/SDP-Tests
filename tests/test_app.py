"""Tests fonctionnels de l'application déployée : chaque page et chaque action du forum."""
import re
import uuid

import pytest
import requests

pytestmark = pytest.mark.functional

TIMEOUT = 10

# La base de SDP démarre vide : chaque test crée ses comptes et ses messages
PASSWORD = "mot-de-passe-de-test"
PASSWORD_MIN_LENGTH = 12
# Comptes de l'ancien db/init.sql et de l'ancien compte admin codé en dur, qui ne doivent plus exister
OLD_DEFAULT_ACCOUNTS = [("alice", "password1"), ("bob", "qwerty"), ("charlie", "letmein"),
                        ("admin", "admin123")]


# --- Fixtures (base_url est dans conftest.py) ----------------------------------

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

        def register(self, username, password=PASSWORD, confirm=None):
            return self.post("/register", data={
                "_csrf": self.csrf_token("/register"), "username": username,
                "password": password, "confirm": password if confirm is None else confirm})

        def login(self, username, password=PASSWORD):
            return self.post("/login", data={"_csrf": self.csrf_token(),
                                             "username": username, "password": password})

        def change_password(self, current, password, confirm=None):
            return self.post("/password", data={
                "_csrf": self.csrf_token("/password"), "current": current,
                "password": password, "confirm": password if confirm is None else confirm})

        def publish(self, content):
            return self.post("/post", data={"_csrf": self.csrf_token("/"), "content": content})

    with Client() as session:
        yield session


def unique(text="Message de test"):
    """Texte introuvable ailleurs dans la base, pour retrouver ce que le test a publié."""
    return f"{text} {uuid.uuid4().hex}"


def new_username():
    """Identifiant libre et valide pour SDP (3 à 50 caractères : lettres, chiffres, . _ -)."""
    return f"user_{uuid.uuid4().hex[:16]}"


@pytest.fixture
def user(client):
    """Navigateur connecté avec un compte tout juste créé (identifiant dans client.username)."""
    client.username = new_username()
    assert client.register(client.username).status_code == 302
    return client


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

    def test_lists_messages_with_author(self, user, base_url):
        content = unique()
        user.publish(content)
        r = requests.get(base_url + "/", timeout=TIMEOUT)
        message = re.search(rf'<div class="msg">((?:(?!</div>).)*{re.escape(content)}.*?)</div>',
                            r.text, re.S).group(1)
        assert f'<span class="author">{user.username}</span>' in message

    def test_messages_are_newest_first(self, user):
        contents = [unique(f"Message {n}") for n in range(3)]  # du plus ancien au plus récent
        for content in contents:
            user.publish(content)
        r = user.get("/")
        positions = [r.text.index(content) for content in contents]
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

    def test_valid_credentials(self, user):
        user.get("/logout")
        r = user.login(user.username)
        assert r.status_code == 302
        assert r.headers["Location"] == "/"
        assert is_logged_in(user.get("/"), user.username)

    def test_logged_in_navigation(self, user):
        r = user.get("/")
        assert 'href="/login"' not in r.text
        assert 'href="/logout"' in r.text
        assert 'href="/password"' in r.text

    def test_wrong_password(self, user):
        user.get("/logout")
        r = user.login(user.username, "mauvais-mot-de-passe")
        assert r.status_code == 200
        assert "Identifiants invalides." in r.text
        assert not is_logged_in(user.get("/"), user.username)

    def test_unknown_user(self, client):
        r = client.post("/login", data={"_csrf": client.csrf_token(),
                                        "username": "inconnu", "password": "x"})
        assert r.status_code == 200
        assert "Identifiants invalides." in r.text

    def test_without_csrf_is_rejected(self, user):
        user.get("/logout")
        r = user.post("/login", data={"username": user.username, "password": PASSWORD})
        assert r.status_code == 403

    def test_with_wrong_csrf_is_rejected(self, user):
        user.get("/logout")
        user.get("/login")
        r = user.post("/login", data={"_csrf": "faux-jeton", "username": user.username,
                                      "password": PASSWORD})
        assert r.status_code == 403
        assert not is_logged_in(user.get("/"), user.username)

    @pytest.mark.parametrize(("username", "password"), OLD_DEFAULT_ACCOUNTS)
    def test_no_default_account(self, client, username, password):
        r = client.login(username, password)
        assert r.status_code == 200
        assert "Identifiants invalides." in r.text

    def test_logout(self, user):
        r = user.get("/logout")
        assert r.status_code == 302
        assert r.headers["Location"] == "/"
        home = user.get("/")
        assert not is_logged_in(home, user.username)
        assert 'href="/login"' in home.text


# --- Création de compte -------------------------------------------------------

class TestRegister:
    def test_form(self, client):
        r = client.get("/register")
        assert r.status_code == 200
        assert 'action="/register"' in r.text
        for field in ('name="_csrf"', 'name="username"', 'name="password" type="password"',
                      'name="confirm" type="password"'):
            assert field in r.text

    def test_link_when_anonymous(self, client):
        assert 'href="/register"' in client.get("/").text

    def test_creates_account_and_logs_in(self, client):
        username = new_username()
        r = client.register(username)
        assert r.status_code == 302
        assert r.headers["Location"] == "/"
        assert is_logged_in(client.get("/"), username)

    def test_duplicate_username(self, user, base_url):
        with requests.Session() as other:
            other.verify = user.verify
            page = other.get(base_url + "/register", timeout=TIMEOUT)
            token = re.search(r'name="_csrf" value="([^"]+)"', page.text).group(1)
            r = other.post(base_url + "/register", timeout=TIMEOUT, allow_redirects=False, data={
                "_csrf": token, "username": user.username,
                "password": "autre-mot-de-passe", "confirm": "autre-mot-de-passe"})
        assert r.status_code == 409
        assert "Cet identifiant est déjà utilisé." in r.text
        # Le compte existant garde son mot de passe
        user.get("/logout")
        assert user.login(user.username).status_code == 302

    @pytest.mark.parametrize("username", ["ab", "a" * 51, "avec espace", "<script>", "é" * 5])
    def test_invalid_username(self, client, username):
        r = client.register(username)
        assert r.status_code == 400
        assert "Identifiant invalide" in r.text
        assert not is_logged_in(client.get("/"), username)

    def test_password_too_short(self, client):
        username = new_username()
        r = client.register(username, "a" * (PASSWORD_MIN_LENGTH - 1))
        assert r.status_code == 400
        assert f"au moins {PASSWORD_MIN_LENGTH} caractères" in r.text
        assert client.login(username, "a" * (PASSWORD_MIN_LENGTH - 1)).status_code == 200

    def test_passwords_must_match(self, client):
        username = new_username()
        r = client.register(username, PASSWORD, "autre-mot-de-passe")
        assert r.status_code == 400
        assert "Les mots de passe ne correspondent pas." in r.text
        assert client.login(username).status_code == 200

    def test_without_csrf_is_rejected(self, client):
        username = new_username()
        client.get("/register")
        r = client.post("/register", data={"username": username, "password": PASSWORD,
                                           "confirm": PASSWORD})
        assert r.status_code == 403
        assert client.login(username).status_code == 200


# --- Changement de mot de passe -----------------------------------------------

class TestPassword:
    NEW_PASSWORD = "nouveau-mot-de-passe"

    def test_anonymous_is_redirected_to_login(self, client):
        r = client.get("/password")
        assert r.status_code == 302
        assert r.headers["Location"] == "/login"

    def test_form(self, user):
        r = user.get("/password")
        assert r.status_code == 200
        assert 'action="/password"' in r.text
        for field in ('name="_csrf"', 'name="current" type="password"',
                      'name="password" type="password"', 'name="confirm" type="password"'):
            assert field in r.text

    def test_change(self, user):
        r = user.change_password(PASSWORD, self.NEW_PASSWORD)
        assert r.status_code == 200
        assert "Mot de passe modifié." in r.text
        user.get("/logout")
        assert user.login(user.username, PASSWORD).status_code == 200
        assert user.login(user.username, self.NEW_PASSWORD).status_code == 302

    def test_wrong_current_password(self, user):
        r = user.change_password("mauvais-mot-de-passe", self.NEW_PASSWORD)
        assert r.status_code == 403
        assert "Mot de passe actuel incorrect." in r.text
        user.get("/logout")
        assert user.login(user.username).status_code == 302

    def test_new_password_too_short(self, user):
        r = user.change_password(PASSWORD, "a" * (PASSWORD_MIN_LENGTH - 1))
        assert r.status_code == 400
        assert f"au moins {PASSWORD_MIN_LENGTH} caractères" in r.text

    def test_passwords_must_match(self, user):
        r = user.change_password(PASSWORD, self.NEW_PASSWORD, "autre-mot-de-passe")
        assert r.status_code == 400
        assert "Les mots de passe ne correspondent pas." in r.text

    def test_without_csrf_is_rejected(self, user):
        r = user.post("/password", data={"current": PASSWORD, "password": self.NEW_PASSWORD,
                                         "confirm": self.NEW_PASSWORD})
        assert r.status_code == 403
        user.get("/logout")
        assert user.login(user.username).status_code == 302


# --- Publication de messages --------------------------------------------------

class TestPost:
    def test_form_when_logged_in(self, user):
        r = user.get("/")
        assert 'action="/post"' in r.text
        assert 'name="_csrf"' in r.text
        assert 'name="content"' in r.text
        assert "Connectez-vous pour publier un message." not in r.text

    def test_publish_message(self, user):
        content = unique()
        r = user.publish(content)
        assert r.status_code == 302
        assert r.headers["Location"] == "/"

        # Le message est affiché en premier, signé par l'utilisateur connecté
        first = re.search(r'<div class="msg">(.*?)</div>', user.get("/").text, re.S).group(1)
        assert content in first
        assert f'<span class="author">{user.username}</span>' in first

    def test_message_visible_by_anonymous(self, user, base_url):
        content = unique()
        user.publish(content)
        assert content in requests.get(base_url + "/", timeout=TIMEOUT).text

    def test_accents_are_kept(self, user):
        content = unique("Éléphant à côté du garçon, ça marche ?")
        user.publish(content)
        assert content in user.get("/").text

    def test_html_is_escaped(self, user):
        content = unique('<script>alert("xss")</script>')
        user.publish(content)
        r = user.get("/")
        assert '<script>alert("xss")</script>' not in r.text
        assert "&lt;script&gt;" in r.text

    def test_anonymous_is_redirected_to_login(self, client):
        content = unique()
        r = client.post("/post", data={"_csrf": client.csrf_token(), "content": content})
        assert r.status_code == 302
        assert r.headers["Location"] == "/login"
        assert content not in client.get("/").text

    def test_without_csrf_is_rejected(self, user):
        content = unique()
        r = user.post("/post", data={"content": content})
        assert r.status_code == 403
        assert content not in user.get("/").text


# --- Recherche ----------------------------------------------------------------

class TestSearch:
    def test_form_without_query(self, client):
        r = client.get("/search")
        assert r.status_code == 200
        assert "<h1>Recherche</h1>" in r.text
        assert 'name="q"' in r.text
        assert "Aucun résultat." not in r.text
        assert '<div class="msg">' not in r.text

    def test_finds_message(self, user, client):
        found, other = unique("Pensez à bien documenter"), unique("Autre message")
        user.publish(found)
        user.publish(other)
        r = client.get("/search", params={"q": found.split()[-1]})
        assert r.status_code == 200
        assert found in r.text
        assert f'<span class="author">{user.username}</span>' in r.text
        # Seul le message correspondant est affiché
        assert other not in r.text

    def test_keeps_query_in_form(self, client):
        r = client.get("/search", params={"q": "documenter"})
        assert 'value="documenter"' in r.text

    def test_is_case_insensitive(self, user):
        content = unique("documenter")
        user.publish(content)
        r = user.get("/search", params={"q": content.upper()})
        assert content in r.text

    def test_with_accents(self, user):
        content = unique("Bienvenue sur le forum du TP sécurité !")
        user.publish(content)
        r = user.get("/search", params={"q": "sécurité ! " + content.split()[-1]})
        assert content in r.text

    @pytest.mark.parametrize("wildcard", ["%", "_"])
    def test_wildcards_are_literal(self, user, wildcard):
        # % et _ sont cherchés tels quels : "ab%" ne trouve pas "abc"
        token = uuid.uuid4().hex
        user.publish(f"{token}x")
        r = user.get("/search", params={"q": token + wildcard})
        assert f"{token}x" not in r.text
        assert "Aucun résultat." in r.text

    def test_no_result(self, client):
        r = client.get("/search", params={"q": unique("introuvable")})
        assert r.status_code == 200
        assert "Aucun résultat." in r.text

    def test_finds_published_message(self, user):
        content = unique()
        user.publish(content)
        r = user.get("/search", params={"q": content.split()[-1]})
        assert content in r.text

    def test_escapes_query(self, client):
        payload = '"><script>alert(1)</script>'
        r = client.get("/search", params={"q": payload})
        assert r.status_code == 200
        assert "<script>alert(1)</script>" not in r.text
