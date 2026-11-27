
"""Hash benchmark results API."""

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from pydantic import ValidationError

from app.schemas.hash_report import (
    HashReport,
    HashResponse,
    validate_report,
)
from app.security.hashing.profiles import PAYLOAD_SIZES

router = APIRouter(
    prefix="/api/v1/lab/crypto",
    tags=["hash-lab"],
)

REPORT_PATH = (
    Path(__file__).resolve().parents[2]
    / "results"
    / "practice-04"
    / "report.json"
)

MAX_REPORT_BYTES = 1048576


def _reject_constant(value: str):
    raise ValueError("non-finite JSON number")


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value

    return result


def load_report() -> HashReport:
    try:
        with REPORT_PATH.open("rb") as stream:
            raw = stream.read(MAX_REPORT_BYTES + 1)

        if len(raw) > MAX_REPORT_BYTES:
            raise ValueError("report too large")

        data = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )

        return validate_report(data)

    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail="hash report not found",
        ) from exc

    except (OSError, ValueError, ValidationError) as exc:
        raise HTTPException(
            status_code=500,
            detail="hash report invalid",
        ) from exc


@router.get(
    "/hash-benchmark-results",
    response_model=HashResponse,
)
def get_hash_benchmark_results(
    payload_bytes: int | None = Query(
        default=None,
        description="Optional payload size: 64, 1024, 65536 or 1048576",
    ),
) -> HashResponse:
    # Validate the complete report before applying any filter.
    report = load_report()

    if payload_bytes is not None and payload_bytes not in PAYLOAD_SIZES:
        raise HTTPException(
            status_code=422,
            detail="unsupported payload_bytes",
        )

    data = report.model_dump()

    if payload_bytes is not None:
        data["results"] = [
            item
            for item in data["results"]
            if item["payload_bytes"] == payload_bytes
        ]

    available_count = sum(
        1 for item in report.algorithms if item.available
    )

    data["summary"] = {
        "algorithms_count": len(report.algorithms),
        "available_count": available_count,
        "results_count": len(data["results"]),
        "checks_count": len(report.checks),
        "all_checks_passed": all(
            item.passed for item in report.checks
        ),
    }

    return HashResponse.model_validate(data)
