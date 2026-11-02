"""Маршрут читання перевіреного звіту криптографічного експерименту."""

import json
import math
from pathlib import Path

from fastapi import APIRouter, HTTPException


router = APIRouter(
    prefix="/api/v1/lab/crypto",
    tags=["crypto-lab"],
)

REPORT_PATH = (
    Path(__file__).resolve().parents[2]
    / "results/practice-02/report.json"
)

EXPECTED_SIZES = {1024, 65536, 1048576}
EXPECTED_BACKENDS = {"cryptography", "pycryptodome"}
EXPECTED_ALGORITHMS = {
    "AES-128-GCM",
    "AES-256-GCM",
    "ChaCha20-Poly1305",
}
EXPECTED_OPERATIONS = {"encrypt", "decrypt"}


def is_positive_number(value) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value > 0
    )


def load_benchmark_report(path: Path) -> dict:
    """Прочитати та перевірити структуру звіту benchmark."""

    try:
        report = json.loads(path.read_text(encoding="utf-8"))

        if not isinstance(report, dict):
            raise ValueError("Report must be an object")

        required_fields = {
            "schema_version",
            "run_id",
            "environment",
            "parameters",
            "results",
        }

        if not required_fields.issubset(report):
            raise ValueError("Missing report fields")

        if report["schema_version"] != 1:
            raise ValueError("Unsupported schema version")

        if not isinstance(report["run_id"], str) or not report["run_id"].strip():
            raise ValueError("Invalid run_id")

        if not isinstance(report["environment"], dict) or not report["environment"]:
            raise ValueError("Invalid environment")

        parameters = report["parameters"]

        if not isinstance(parameters, dict):
            raise ValueError("Invalid parameters")

        if parameters.get("sizes_bytes") != [1024, 65536, 1048576]:
            raise ValueError("Invalid message sizes")

        if parameters.get("warmup") != 10:
            raise ValueError("Invalid warmup")

        if parameters.get("series") != 5:
            raise ValueError("Invalid series count")

        if parameters.get("operations_per_series") != 100:
            raise ValueError("Invalid operations count")

        if parameters.get("context_bytes") != 64:
            raise ValueError("Invalid context length")

        if not isinstance(parameters.get("include_cipher_object_creation"), bool):
            raise ValueError("Invalid object creation parameter")

        results = report["results"]

        if not isinstance(results, list) or len(results) != 36:
            raise ValueError("Expected 36 result rows")

        combinations = set()

        for item in results:
            if not isinstance(item, dict):
                raise ValueError("Invalid result row")

            backend = item.get("backend")
            algorithm = item.get("algorithm")
            size = item.get("size_bytes")
            operation = item.get("operation")

            if backend not in EXPECTED_BACKENDS:
                raise ValueError("Invalid backend")

            if algorithm not in EXPECTED_ALGORITHMS:
                raise ValueError("Invalid algorithm")

            if size not in EXPECTED_SIZES:
                raise ValueError("Invalid message size")

            if operation not in EXPECTED_OPERATIONS:
                raise ValueError("Invalid operation")

            combination = (backend, algorithm, size, operation)

            if combination in combinations:
                raise ValueError("Duplicate result row")

            combinations.add(combination)

            series_means = item.get("series_mean_ns")

            if (
                not isinstance(series_means, list)
                or len(series_means) != 5
                or not all(is_positive_number(x) for x in series_means)
            ):
                raise ValueError("Invalid series means")

            for metric in (
                "median_ns",
                "iqr_ns",
                "throughput_mib_s",
            ):
                if not is_positive_number(item.get(metric)):
                    raise ValueError("Invalid result metric")

        if len(combinations) != 36:
            raise ValueError("Incomplete benchmark results")

        return report

    except FileNotFoundError:
        raise

    except Exception as exc:
        raise ValueError("Invalid benchmark report") from exc


@router.get("/benchmark-results")
def get_benchmark_results():
    """Повернути звіт без запуску нового експерименту."""

    try:
        return load_benchmark_report(REPORT_PATH)

    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail="Benchmark results unavailable",
        )

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Benchmark results unavailable",
        )