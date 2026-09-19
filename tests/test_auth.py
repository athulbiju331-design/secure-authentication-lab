
import os
import tempfile

import pytest

from app import app, get_db, init_db, login_attempts


@pytest.fixture()
def client(monkeypatch):
    fd, path = tempfile.mkstemp()

    app.config.update(
        TESTING=True,
        SECRET_KEY="test-secret",
    )

    monkeypatch.setattr("app.DATABASE", path)

    # Reset rate limiter before every test
    login_attempts.clear()

    with app.test_client() as client:
        with app.app_context():
            init_db()

        yield client

    os.close(fd)
    os.unlink(path)


def csrf(client):
    """Create and return a valid CSRF token."""
    client.get("/register")

    with client.session_transaction() as session:
        return session["_csrf_token"]


def register(client, username="alice", password="StrongPass123!"):
    return client.post(
        "/register",
        data={
            "username": username,
            "password": password,
            "_csrf_token": csrf(client),
        },
    )


def login(client, username="alice", password="StrongPass123!"):
    return client.post(
        "/login",
        data={
            "username": username,
            "password": password,
            "_csrf_token": csrf(client),
        },
    )


def test_registration_and_hash(client):
    response = register(client)

    assert response.status_code == 302

    row = get_db().execute(
        "SELECT password_hash FROM users WHERE username=?",
        ("alice",),
    ).fetchone()

    assert row["password_hash"] != "StrongPass123!"
    assert row["password_hash"].startswith("scrypt:")


def test_valid_login(client):
    register(client)

    response = login(client)

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard")


def test_generic_invalid_login(client):
    register(client)

    response = login(
        client,
        password="WrongPassword123!",
    )

    assert response.status_code == 401
    assert b"Invalid username or password." in response.data
    assert b"Username does not exist" not in response.data


def test_server_validation(client):
    response = client.post(
        "/register",
        data={
            "username": "a",
            "password": "short",
            "_csrf_token": csrf(client),
        },
    )

    assert response.status_code == 400


def test_rate_limit(client):
    register(client)

    # First five failed attempts should return 401
    for _ in range(5):
        response = login(
            client,
            password="WrongPassword123!",
        )
        assert response.status_code == 401

    # Sixth failed attempt should trigger rate limiting
    response = login(
        client,
        password="WrongPassword123!",
    )

    assert response.status_code == 429


def test_logout_and_csrf(client):
    register(client)
    login(client)

    # Missing CSRF token
    response = client.post("/logout", data={})
    assert response.status_code == 400

    # Valid CSRF token
    response = client.post(
        "/logout",
        data={
            "_csrf_token": csrf(client),
        },
    )

    assert response.status_code == 302

    # Dashboard should require login again
    response = client.get("/dashboard")
    assert response.status_code == 302


def test_protected_page(client):
    response = client.get("/dashboard")
    assert response.status_code == 302


def test_cookie_attributes(client):
    register(client)

    response = login(client)

    cookie = response.headers.get("Set-Cookie", "")

    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


def test_csrf_rejection(client):
    response = client.post(
        "/register",
        data={
            "username": "bob",
            "password": "StrongPass123!",
        },
    )

    assert response.status_code == 400