
"""Ці тести не потребують готових або вигаданих вимірювань."""

import copy
import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.main import app
from app.api import asymmetric_lab as lab
from app.schemas.asymmetric_report import (
    Experiment,
    validate_complete_report,
)

ROUTE = "/api/v1/lab/crypto/asymmetric-benchmark-results"
REPORT_FILE = (
    Path(__file__).resolve().parents[1]
    / "results"
    / "practice-03"
    / "report.json"
)


@pytest.fixture
def valid_report():
    with REPORT_FILE.open(encoding="utf-8") as file:
        return json.load(file)


def test_missing_report_reader(tmp_path, monkeypatch):
    monkeypatch.setattr(lab, "REPORT_PATH", tmp_path / "absent.json")

    with pytest.raises(HTTPException) as error:
        lab.load_report()

    assert error.value.status_code == 404
    assert error.value.detail == "benchmark report not found"


@pytest.mark.parametrize(
    "raw",
    [b"{", b'{"x":1,"x":2}', b'{"x":NaN}', b"{}"],
)
def test_invalid_report_reader(tmp_path, monkeypatch, raw):
    path = tmp_path / "bad.json"
    path.write_bytes(raw)
    monkeypatch.setattr(lab, "REPORT_PATH", path)

    with pytest.raises(HTTPException) as error:
        lab.load_report()

    assert error.value.status_code == 500
    assert error.value.detail == "benchmark report invalid"


def test_route_registered():
    paths = app.openapi()["paths"]

    assert ROUTE in paths
    assert "get" in paths[ROUTE]


def test_api_missing_report(tmp_path, monkeypatch):
    monkeypatch.setattr(lab, "REPORT_PATH", tmp_path / "absent.json")

    response = TestClient(app).get(ROUTE)

    assert response.status_code == 404
    assert response.json() == {"detail": "benchmark report not found"}


def test_api_invalid_report(tmp_path, monkeypatch):
    path = tmp_path / "bad.json"
    path.write_bytes(b"not json")
    monkeypatch.setattr(lab, "REPORT_PATH", path)

    response = TestClient(app).get(ROUTE)

    assert response.status_code == 500
    assert response.json() == {"detail": "benchmark report invalid"}


@pytest.mark.parametrize("value", [True, 5.0, "5"])
def test_metadata_requires_exact_integer(value):
    metadata = {
        "series": value,
        "operations_per_series": 20,
        "warmup": 10,
        "keygen_runs": 5,
        "direct_payload_bytes": 64,
        "hybrid_sizes_bytes": [1024, 65536, 1048576],
        "source_commit": "0" * 40,
        "created_at_utc": "2026-10-07T00:00:00Z",
    }

    with pytest.raises(ValidationError):
        Experiment.model_validate(metadata)


def test_report_limit(tmp_path, monkeypatch):
    path = tmp_path / "oversize.json"
    path.write_bytes(b"x" * (lab.MAX_REPORT_BYTES + 1))
    monkeypatch.setattr(lab, "REPORT_PATH", path)

    with pytest.raises(HTTPException) as error:
        lab.load_report()

    assert error.value.status_code == 500
    assert error.value.detail == "benchmark report invalid"


def test_valid_measured_report(valid_report):
    report = validate_complete_report(valid_report)

    assert len(report.results) == 22
    assert len(report.checks) == 22
    assert len(report.key_generation) == 4


def test_duplicate_result_tuple_rejected(valid_report):
    data = copy.deepcopy(valid_report)
    data["results"][1] = copy.deepcopy(data["results"][0])

    with pytest.raises(
        ValueError,
        match="duplicate benchmark result",
    ):
        validate_complete_report(data)


def test_missing_result_coverage_rejected(valid_report):
    data = copy.deepcopy(valid_report)
    data["results"].pop()

    with pytest.raises(ValidationError):
        validate_complete_report(data)


def test_duplicate_check_rejected(valid_report):
    data = copy.deepcopy(valid_report)
    data["checks"][1] = copy.deepcopy(data["checks"][0])

    with pytest.raises(ValueError, match="duplicate check"):
        validate_complete_report(data)


def test_missing_check_coverage_rejected(valid_report):
    data = copy.deepcopy(valid_report)
    data["checks"].pop()

    with pytest.raises(ValidationError):
        validate_complete_report(data)


def test_extra_result_field_rejected(valid_report):
    data = copy.deepcopy(valid_report)
    data["results"][0]["unexpected"] = "value"

    with pytest.raises(ValidationError):
        validate_complete_report(data)


def test_wrong_numeric_type_rejected(valid_report):
    data = copy.deepcopy(valid_report)
    data["results"][0]["median_ns"] = "not a number"

    with pytest.raises(ValidationError):
        validate_complete_report(data)


@pytest.mark.parametrize(
    "value",
    [float("nan"), float("inf"), float("-inf")],
)
def test_non_finite_measurement_rejected(valid_report, value):
    data = copy.deepcopy(valid_report)
    data["results"][0]["median_ns"] = value

    with pytest.raises(ValidationError):
        validate_complete_report(data)


def test_negative_measurement_rejected(valid_report):
    data = copy.deepcopy(valid_report)
    data["results"][0]["median_ns"] = -1.0

    with pytest.raises(ValidationError):
        validate_complete_report(data)


def test_incorrect_throughput_formula_rejected(valid_report):
    data = copy.deepcopy(valid_report)

    hybrid_result = next(
        item
        for item in data["results"]
        if item["group"] == "hybrid"
    )

    hybrid_result["throughput_mib_s"] *= 2

    with pytest.raises(ValueError, match="incorrect throughput"):
        validate_complete_report(data)


def test_failed_correctness_check_remains_visible(valid_report):
    data = copy.deepcopy(valid_report)
    data["checks"][0]["passed"] = False

    report = validate_complete_report(data)

    assert report.checks[0].passed is False


def test_api_returns_complete_report():
    response = TestClient(app).get(ROUTE)

    assert response.status_code == 200

    data = response.json()

    assert data["schema_version"] == 1
    assert len(data["key_generation"]) == 4
    assert len(data["results"]) == 22
    assert len(data["checks"]) == 22
    assert all(check["passed"] is True for check in data["checks"])


def test_api_variant_payload_bytes():
    client = TestClient(app)

    for size, expected in [(64, 4), (1024, 6)]:
        response = client.get(ROUTE, params={"payload_bytes": size})

        assert response.status_code == 200

        data = response.json()

        assert len(data["results"]) == expected
        assert all(
            item["payload_bytes"] == size
            for item in data["results"]
        )
        assert len(data["key_generation"]) == 4
        assert len(data["checks"]) == 22


def test_api_variant_rejects_invalid_payload_size():
    response = TestClient(app).get(
        ROUTE,
        params={"payload_bytes": 128},
    )

    assert response.status_code == 422


def test_api_does_not_run_benchmark(monkeypatch):
    import benchmarks.asymmetric_benchmark as benchmark

    def forbidden():
        raise AssertionError("HTTP request must not run benchmark")

    monkeypatch.setattr(benchmark, "run_experiment", forbidden)

    response = TestClient(app).get(ROUTE)

    assert response.status_code == 200


def test_api_has_no_file_path_parameter():
    operation = app.openapi()["paths"][ROUTE]["get"]
    parameters = operation.get("parameters", [])

    assert all(item["name"] != "path" for item in parameters)


def test_api_response_contains_no_secret_material():
    response = TestClient(app).get(ROUTE)

    assert response.status_code == 200

    body = response.json()

    forbidden_names = {
        "private_key",
        "secret_key",
        "aes_key",
        "plaintext",
        "ciphertext",
        "envelope",
    }

    def inspect(value):
        if isinstance(value, dict):
            assert not (forbidden_names & set(value))

            for child in value.values():
                inspect(child)

        elif isinstance(value, list):
            for child in value:
                inspect(child)

    inspect(body)
