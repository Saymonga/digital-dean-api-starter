"""Isolated synthetic fixtures; no real database, account or secret."""
import pytest
from fastapi.testclient import TestClient

from app.api.accounts import get_user_repository
from app.db.initialize import initialize_database
from app.main import app
from app.repositories.user_repository import UserRepository
from app.schemas.user_account import UserCreate

PASSWORD = "Learning only 05!"
PUBLIC_KEYS = {"id", "name", "email", "login", "status_id"}


def account_data(login="demo_student", status_id=0, **changes):
    data = dict(name="Навчальний користувач", email=f"{login}@example.com",
                login=login, password=PASSWORD, status_id=status_id)
    data.update(changes)
    return UserCreate(**data)


@pytest.fixture
def account_database(tmp_path):
    path = tmp_path / "isolated.sqlite3"
    initialize_database(path)
    return path


@pytest.fixture
def account_repository(account_database):
    return UserRepository(account_database)


@pytest.fixture
def account_client(account_repository):
    sentinel = object()
    previous = app.dependency_overrides.get(get_user_repository, sentinel)
    app.dependency_overrides[get_user_repository] = lambda: account_repository
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            yield client
    finally:
        if previous is sentinel:
            app.dependency_overrides.pop(get_user_repository, None)
        else:
            app.dependency_overrides[get_user_repository] = previous
