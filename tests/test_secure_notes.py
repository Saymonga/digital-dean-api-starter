
"""Моделі та HTTP-контракт; усі записи вигадані."""

from dataclasses import replace
import json
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import app
from app.schemas.secure_note import NoteCreate
from app.schemas.student import StudentCreate
from app.repositories.student_repository import student_repository
from app.repositories.secure_note_repository import repository as note_repository
from app.security.keys import create_process_key


@pytest.fixture
def client():
    student_repository.clear()
    note_repository.clear()

    with TestClient(app) as test_client:
        yield test_client

    student_repository.clear()
    note_repository.clear()


@pytest.fixture
def student(client):
    payload = StudentCreate(
        full_name="Test Student",
        email=f"{uuid4()}@example.com",
        group_code="КН-01",
        enrollment_year=2025,
    )
    return student_repository.create(payload)


@pytest.mark.parametrize(
    "text",
    ("x" * 4096, "я" * 2048, "  текст  "),
)
def test_accepted_text_is_preserved(text):
    assert NoteCreate(text=text).text == text


@pytest.mark.parametrize(
    "payload",
    (
        {"text": ""},
        {"text": " "},
        {"text": "x" * 4097},
        {"text": "я" * 2049},
        {"text": 42},
        {"text": "demo", "key": "do-not-accept"},
    ),
)
def test_invalid_note_input(payload):
    with pytest.raises(ValidationError):
        NoteCreate(**payload)


def test_unknown_student_is_not_found(client):
    response = client.get(
        f"/api/v1/students/{uuid4()}/secure-notes/{uuid4()}"
    )
    assert response.status_code == 404


def test_note_api_and_internal_storage(client, student):
    text = "Тестова захищена нотатка"

    response = client.post(
        f"/api/v1/students/{student.id}/secure-notes",
        json={"text": text, "category": "academic"},
    )

    assert response.status_code == 201
    created = response.json()

    assert created["student_id"] == str(student.id)
    assert created["algorithm"] == "AES-256-GCM"
    assert created["category"] == "academic"

    for field in ("text", "key", "ciphertext", "nonce", "tag"):
        assert field not in created

    note_id = UUID(created["id"])
    stored = note_repository.get(student.id, note_id)

    assert not hasattr(stored, "text")
    assert not hasattr(stored, "key")
    assert len(stored.nonce) == 12
    assert len(stored.tag) == 16
    assert text.encode("utf-8") not in stored.ciphertext

    read_response = client.get(
        f"/api/v1/students/{student.id}/secure-notes/{note_id}"
    )

    assert read_response.status_code == 200
    assert read_response.json()["text"] == text
    assert read_response.json()["category"] == "academic"


def test_damaged_note_is_rejected_without_plaintext(client, student):
    response = client.post(
        f"/api/v1/students/{student.id}/secure-notes",
        json={"text": "Secret text", "category": "general"},
    )

    assert response.status_code == 201

    note_id = UUID(response.json()["id"])
    note = note_repository.get(student.id, note_id)

    damaged = replace(
        note,
        ciphertext=bytes([note.ciphertext[0] ^ 1])
        + note.ciphertext[1:],
    )
    note_repository._items[note_id] = damaged

    read_response = client.get(
        f"/api/v1/students/{student.id}/secure-notes/{note_id}"
    )

    assert read_response.status_code == 500
    assert read_response.json()["detail"] == "Protected note unavailable"
    assert "Secret text" not in read_response.text
    assert "Traceback" not in read_response.text


def test_nonce_limit_rejects_only_new_writes(client, student):
    app.state.process_key = create_process_key(limit=2)

    url = f"/api/v1/students/{student.id}/secure-notes"

    first = client.post(url, json={"text": "First note"})
    second = client.post(url, json={"text": "Second note"})
    third = client.post(url, json={"text": "Third note"})

    assert first.status_code == 201
    assert second.status_code == 201
    assert third.status_code == 503

    previous = client.get(
        f"{url}/{first.json()['id']}"
    )

    assert previous.status_code == 200
    assert previous.json()["text"] == "First note"


def test_benchmark_report_reader(tmp_path, client, monkeypatch):
    from app.api import crypto_lab

    valid_report = {
        "schema_version": 1,
        "run_id": "test-run",
        "environment": {"python": "test"},
        "parameters": {
            "sizes_bytes": [1024, 65536, 1048576],
            "warmup": 10,
            "series": 5,
            "operations_per_series": 100,
            "context_bytes": 64,
            "include_cipher_object_creation": False,
        },
        "results": [],
    }

    for backend in ("cryptography", "pycryptodome"):
        for algorithm in (
            "AES-128-GCM",
            "AES-256-GCM",
            "ChaCha20-Poly1305",
        ):
            for size in (1024, 65536, 1048576):
                for operation in ("encrypt", "decrypt"):
                    valid_report["results"].append({
                        "backend": backend,
                        "algorithm": algorithm,
                        "size_bytes": size,
                        "operation": operation,
                        "series_mean_ns": [100.0] * 5,
                        "median_ns": 100.0,
                        "iqr_ns": 1.0,
                        "throughput_mib_s": 10.0,
                    })

    report_path = tmp_path / "report.json"
    monkeypatch.setattr(crypto_lab, "REPORT_PATH", report_path)

    response = client.get("/api/v1/lab/crypto/benchmark-results")
    assert response.status_code == 404

    report_path.write_text(
        json.dumps(valid_report),
        encoding="utf-8",
    )

    response = client.get("/api/v1/lab/crypto/benchmark-results")
    assert response.status_code == 200
    assert len(response.json()["results"]) == 36

    report_path.write_text(
        '{"schema_version": 1}',
        encoding="utf-8",
    )

    response = client.get("/api/v1/lab/crypto/benchmark-results")
    assert response.status_code == 500
    assert response.json()["detail"] == "Benchmark results unavailable"
