
import pytest
from fastapi.testclient import TestClient
from uuid import uuid4

from app.main import app
from app.repositories.student_repository import student_repository


client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_repository():
    student_repository.clear()
    yield
    student_repository.clear()


def create_student(email="student@example.com", enrollment_year=2024):
    return client.post(
        "/api/v1/students",
        json={
            "full_name": "Тестовый Студент",
            "email": email,
            "group_code": "B2F501ДОН24",
            "enrollment_year": enrollment_year,
        },
    )


# 1. Успішне створення запису
def test_create_student():
    response = create_student()

    assert response.status_code == 201
    assert response.json()["full_name"] == "Тестовый Студент"
    assert response.json()["email"] == "student@example.com"
    assert "id" in response.json()


# 2. Відхилення некоректних даних
def test_create_student_invalid_data():
    response = client.post(
        "/api/v1/students",
        json={
            "full_name": "A",
            "email": "invalid-email",
            "group_code": "B2F501ДОН24",
            "enrollment_year": 2024,
        },
    )

    assert response.status_code == 422


# 3. Отримання списку студентів
def test_list_students():
    create_student("first@example.com")
    create_student("second@example.com")

    response = client.get("/api/v1/students")

    assert response.status_code == 200
    assert len(response.json()) == 2


# 4. Отримання наявного запису
def test_get_student():
    created = create_student()
    student_id = created.json()["id"]

    response = client.get(f"/api/v1/students/{student_id}")

    assert response.status_code == 200
    assert response.json()["id"] == student_id


# 5. Відповідь 404 для відсутнього запису
def test_get_missing_student():
    student_id = uuid4()

    response = client.get(f"/api/v1/students/{student_id}")

    assert response.status_code == 404


# 6. Часткове оновлення
def test_update_student():
    created = create_student()
    student_id = created.json()["id"]

    response = client.patch(
        f"/api/v1/students/{student_id}",
        json={"full_name": "Оновлений Студент"},
    )

    assert response.status_code == 200
    assert response.json()["full_name"] == "Оновлений Студент"
    assert response.json()["email"] == "student@example.com"


# 7. Відхилення невідомого поля
def test_reject_unknown_field():
    response = client.post(
        "/api/v1/students",
        json={
            "full_name": "Тестовый Студент",
            "email": "student@example.com",
            "group_code": "B2F501ДОН24",
            "enrollment_year": 2024,
            "unknown_field": "unexpected",
        },
    )

    assert response.status_code == 422


# 8. Фільтрація за полем індивідуального варіанта
def test_filter_by_enrollment_year():
    create_student("first@example.com", 2024)
    create_student("second@example.com", 2025)

    response = client.get(
        "/api/v1/students",
        params={"enrollment_year": 2024},
    )

    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["enrollment_year"] == 2024


# 9. Перевірка мінімального значення року вступу
def test_enrollment_year_below_minimum():
    response = create_student(
        "old@example.com",
        enrollment_year=1999,
    )

    assert response.status_code == 422


# 10. Перевірка максимального значення року вступу
def test_enrollment_year_above_maximum():
    response = create_student(
        "future@example.com",
        enrollment_year=2101,
    )

    assert response.status_code == 422
