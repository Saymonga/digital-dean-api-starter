"""Initial API checks; new endpoints must be connected to app.main.app."""
import pytest

from app.db.connection import open_database
from app.main import app
from tests.practice05_support import (
    PASSWORD, PUBLIC_KEYS, account_client, account_data, account_database,
    account_repository,
)


def body(login="demo_student", status_id=0, **changes):
    data = dict(name="Навчальний користувач", email=f"{login}@example.com",
                login=login, password=PASSWORD, status_id=status_id)
    data.update(changes)
    return data


def test_routes_are_in_existing_application():
    paths = app.openapi()["paths"]
    for path, method in [("/api/v1/users", "post"),
                         ("/api/v1/users/{user_id}", "delete"),
                         ("/api/v1/users/{user_id}/block", "patch"),
                         ("/api/v1/auth/login", "post")]:
        assert method in paths.get(path, {})
    assert "get" in paths.get("/health", {})
    assert "post" in paths.get("/api/v1/students", {})
    assert "get" in paths.get("/api/v1/lab/crypto/hash-benchmark-results", {})


def test_default_status_and_safe_representation(account_client, account_database):
    data = body()
    data.pop("status_id")
    response = account_client.post("/api/v1/users", json=data)
    assert response.status_code == 201
    public = response.json()
    assert set(public) == PUBLIC_KEYS and type(public["id"]) is int
    assert public["status_id"] == 0 and PASSWORD not in response.text
    with open_database(account_database) as con:
        row = con.execute('SELECT password,salt FROM "user" WHERE id=?', (public["id"],)).fetchone()
        assert row[0].startswith("pbkdf2_sha256$600000$")
        assert row[0] != PASSWORD and len(row[1]) == 32


@pytest.mark.parametrize("status_id,expected", [(0, False), (1, True), (2, False)])
def test_login_is_json_boolean_and_checks_status(account_client, status_id, expected):
    assert account_client.post("/api/v1/users", json=body(status_id=status_id)).status_code == 201
    response = account_client.post("/api/v1/auth/login", json={"login": "demo_student", "password": PASSWORD})
    assert response.status_code == 200
    assert response.json() is expected
    assert response.text in ("true", "false")


def test_wrong_unknown_and_sql_like_credentials_are_false(account_client):
    account_client.post("/api/v1/users", json=body(status_id=1))
    for login, password in [("demo_student", "Wrong password 05!"),
                            ("unknown_student", PASSWORD),
                            ("' OR 1=1 --", PASSWORD)]:
        response = account_client.post("/api/v1/auth/login", json={"login": login, "password": password})
        assert response.status_code == 200 and response.json() is False


def test_block_is_persistent_and_idempotent(account_client, account_database):
    created = account_client.post("/api/v1/users", json=body(status_id=1)).json()
    for _ in range(2):
        response = account_client.patch(f'/api/v1/users/{created["id"]}/block')
        assert response.status_code == 200
        assert set(response.json()) == PUBLIC_KEYS
        assert response.json() == {**created, "status_id": 2}
    login = account_client.post("/api/v1/auth/login", json={"login": "demo_student", "password": PASSWORD})
    assert login.json() is False
    with open_database(account_database) as con:
        assert con.execute('SELECT status_id FROM "user" WHERE id=?', (created["id"],)).fetchone()[0] == 2


def test_delete_has_empty_body_and_then_404(account_client):
    created = account_client.post("/api/v1/users", json=body(status_id=1)).json()
    path = f'/api/v1/users/{created["id"]}'
    response = account_client.delete(path)
    assert response.status_code == 204 and response.content == b""
    assert account_client.delete(path).status_code == 404
    assert account_client.patch(path + "/block").status_code == 404
    response = account_client.post("/api/v1/auth/login", json={"login": "demo_student", "password": PASSWORD})
    assert response.json() is False


@pytest.mark.parametrize("change", [{"email": "other@example.com"},
                                  {"login": "other_student", "email": "demo_student@example.com"},
                                  {"login": "other_student", "email": "DEMO_STUDENT@example.com"}])
def test_duplicate_login_or_canonical_email_is_409(account_client, change):
    assert account_client.post("/api/v1/users", json=body()).status_code == 201
    response = account_client.post("/api/v1/users", json=body(**change))
    assert response.status_code == 409 and PASSWORD not in response.text


@pytest.mark.parametrize("change", [{"status_id": 3}, {"status_id": True},
                                  {"status_id": "1"}, {"status_id": 1.0},
                                  {"password": "short"}, {"salt": "client_salt"},
                                  {"id": 123}, {"role_id": 1},
                                  {"email": "not-an-email"}, {"name": "   "}])
def test_invalid_registration_is_422_without_input_echo(account_client, change):
    response = account_client.post("/api/v1/users", json=body(**change))
    assert response.status_code == 422
    assert PASSWORD not in response.text and "client_salt" not in response.text
    assert "input" not in response.json()["detail"][0]


def test_malformed_json_error_does_not_echo_password(account_client):
    secret = "Synthetic parser marker 05"
    response = account_client.post("/api/v1/auth/login",
        content='{"login":"demo_student","password":"' + secret + '"',
        headers={"Content-Type": "application/json"})
    assert response.status_code == 422 and secret not in response.text


@pytest.mark.parametrize("path", ["0", "-1", "not-an-id", "9223372036854775808"])
def test_invalid_id_is_422(account_client, path):
    assert account_client.delete("/api/v1/users/" + path).status_code == 422
