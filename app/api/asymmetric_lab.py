
"""API endpoint for the saved asymmetric cryptography benchmark report."""

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from pydantic import ValidationError

from app.schemas.asymmetric_report import (
    BenchmarkReport,
    BenchmarkResponse,
    validate_complete_report,
)


router = APIRouter(
    prefix="/api/v1/lab/crypto",
    tags=["asymmetric-lab"],
)

REPORT_PATH = (
    Path(__file__).resolve().parents[2]
    / "results"
    / "practice-03"
    / "report.json"
)

MAX_REPORT_BYTES = 1_048_576
ALLOWED_PAYLOAD_SIZES = {64, 1024, 65536, 1048576}


def _reject_constant(value: str):
    raise ValueError(f"Invalid JSON constant: {value}")


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}

    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value

    return result


def load_report() -> BenchmarkReport:
    """Read and validate the complete report from the fixed path."""
    try:
        with REPORT_PATH.open("rb") as report_file:
            raw = report_file.read(MAX_REPORT_BYTES + 1)

        if len(raw) > MAX_REPORT_BYTES:
            raise ValueError("Report exceeds the maximum allowed size")

        data = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )

        return validate_complete_report(data)

    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail="benchmark report not found",
        ) from exc

    except (
        OSError,
        ValueError,
        UnicodeDecodeError,
        ValidationError,
        TypeError,
    ) as exc:
        raise HTTPException(
            status_code=500,
            detail="benchmark report invalid",
        ) from exc


@router.get(
    "/asymmetric-benchmark-results",
    response_model=BenchmarkResponse,
)
def get_asymmetric_benchmark_results(
    payload_bytes: int | None = Query(default=None),
) -> BenchmarkResponse:
    """Return the validated benchmark report, optionally filtered by payload size."""
    report = load_report()

    if payload_bytes is not None and payload_bytes not in ALLOWED_PAYLOAD_SIZES:
        raise HTTPException(
            status_code=422,
            detail="payload_bytes must be one of 64, 1024, 65536, 1048576",
        )

    response_data = report.model_dump()

    if payload_bytes is not None:
        response_data["results"] = [
            item
            for item in response_data["results"]
            if item["payload_bytes"] == payload_bytes
        ]

    return BenchmarkResponse.model_validate(response_data)
