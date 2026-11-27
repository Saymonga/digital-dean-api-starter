
"""Strict schema and semantic validation for the hash benchmark report."""

from datetime import datetime, timedelta
import math
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StrictInt,
)

from app.security.hashing.profiles import (
    AlgorithmID,
    Mode,
    PROFILES,
    PAYLOAD_SIZES,
    CHUNK_BYTES,
    SERIES,
    WARMUP,
    AVALANCHE_TRIALS,
    AVALANCHE_BYTES,
    CHECK_NAMES,
    repeat_count,
)


def _exact_int(value):
    if type(value) is not int:
        raise ValueError("integer required; bool/float/string is not an integer")
    return value


Version = Annotated[Literal[1], BeforeValidator(_exact_int)]
Int5 = Annotated[Literal[5], BeforeValidator(_exact_int)]
Int10 = Annotated[Literal[10], BeforeValidator(_exact_int)]
Int100 = Annotated[Literal[100], BeforeValidator(_exact_int)]
Int1000 = Annotated[Literal[1000], BeforeValidator(_exact_int)]
Int1024 = Annotated[Literal[1024], BeforeValidator(_exact_int)]
Int16384 = Annotated[Literal[16384], BeforeValidator(_exact_int)]

PositiveInt = Annotated[StrictInt, Field(gt=0)]
NonnegativeInt = Annotated[StrictInt, Field(ge=0)]
Positive = Annotated[float, Field(gt=0)]
Nonnegative = Annotated[float, Field(ge=0)]


class StrictModel(BaseModel):
    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        allow_inf_nan=False,
    )


class Parameters(StrictModel):
    sizes: list[PositiveInt] = Field(min_length=4, max_length=4)
    chunk_bytes: Int16384
    warmup: Int10
    series: Int5
    repeats_small: Int1000
    repeats_large: Int100
    avalanche_trials: Int100
    avalanche_bytes: Int1024


class Environment(StrictModel):
    python: str = Field(min_length=1, max_length=160)
    openssl_ssl: str = Field(min_length=1, max_length=160)
    os: str = Field(min_length=1, max_length=240)
    cpu: str = Field(min_length=1, max_length=160)
    architecture: str = Field(min_length=1, max_length=80)


class AlgorithmStatus(StrictModel):
    algorithm: AlgorithmID
    available: bool
    reason: Literal["not_available_in_environment"] | None
    implementation: str | None = Field(max_length=160)


class PerformanceResult(StrictModel):
    algorithm: AlgorithmID
    mode: Mode
    payload_bytes: PositiveInt
    digest_bytes: PositiveInt
    repeats: PositiveInt
    median_ns: Positive
    iqr_ns: Nonnegative
    throughput_mib_s: Positive


class AvalancheResult(StrictModel):
    algorithm: AlgorithmID
    input_bytes: Int1024
    trials: Int100
    digest_bits: PositiveInt
    min_flipped_bits: NonnegativeInt
    max_flipped_bits: NonnegativeInt
    mean_flipped_bits: Nonnegative
    mean_fraction: float = Field(ge=0, le=1)


class CorrectnessCheck(StrictModel):
    algorithm: AlgorithmID
    name: Literal[
        "known-abc",
        "known-empty",
        "unicode-utf8",
        "determinism",
        "digest-length",
        "stream-equivalence",
    ]
    passed: bool


class Summary(StrictModel):
    algorithms_count: PositiveInt
    available_count: PositiveInt
    results_count: NonnegativeInt
    checks_count: NonnegativeInt
    all_checks_passed: bool


class HashReport(StrictModel):
    schema_version: Version
    created_at: str = Field(min_length=20, max_length=40)
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    parameters: Parameters
    environment: Environment
    algorithms: list[AlgorithmStatus] = Field(
        min_length=7,
        max_length=7,
    )
    results: list[PerformanceResult] = Field(
        min_length=40,
        max_length=56,
    )
    avalanche: list[AvalancheResult] = Field(
        min_length=5,
        max_length=7,
    )
    checks: list[CorrectnessCheck] = Field(
        min_length=30,
        max_length=42,
    )


class HashResponse(HashReport):
    results: list[PerformanceResult] = Field(max_length=56)
    summary: Summary | None = None


def validate_report(data: object) -> HashReport:
    """Validate report structure, coverage and semantic consistency."""

    report = HashReport.model_validate(data)

    params = report.parameters

    if params.sizes != list(PAYLOAD_SIZES):
        raise ValueError("invalid payload sizes")

    if params.chunk_bytes != CHUNK_BYTES:
        raise ValueError("invalid chunk size")

    if params.series != SERIES or params.warmup != WARMUP:
        raise ValueError("invalid benchmark parameters")

    if params.avalanche_trials != AVALANCHE_TRIALS:
        raise ValueError("invalid avalanche trials")

    if params.avalanche_bytes != AVALANCHE_BYTES:
        raise ValueError("invalid avalanche input size")

    # Validate UTC timestamp.
    try:
        created = datetime.fromisoformat(
            report.created_at.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise ValueError("invalid created_at") from exc

    if created.tzinfo is None or created.utcoffset() != timedelta(0):
        raise ValueError("created_at must be UTC")

    # Validate algorithm statuses.
    statuses = {}

    for item in report.algorithms:
        if item.algorithm in statuses:
            raise ValueError("duplicate algorithm status")
        statuses[item.algorithm] = item

    if set(statuses) != set(PROFILES):
        raise ValueError("invalid algorithm coverage")

    available = set()

    for algorithm, status in statuses.items():
        profile = PROFILES[algorithm]

        if status.available:
            if status.reason is not None:
                raise ValueError("available algorithm has a reason")

            if not status.implementation:
                raise ValueError("missing implementation name")

            available.add(algorithm)

        else:
            if not profile.legacy:
                raise ValueError("required algorithm unavailable")

            if status.reason != "not_available_in_environment":
                raise ValueError("invalid unavailable reason")

            if status.implementation is not None:
                raise ValueError("unavailable algorithm has implementation")

    # Validate the complete performance matrix.
    expected_results = {
        (algorithm, mode, size)
        for algorithm in available
        for mode in ("whole", "chunked")
        for size in PAYLOAD_SIZES
    }

    actual_results = set()

    for item in report.results:
        key = (
            item.algorithm,
            item.mode,
            item.payload_bytes,
        )

        if key in actual_results:
            raise ValueError("duplicate performance result")

        actual_results.add(key)

        if item.algorithm not in available:
            raise ValueError("result for unavailable algorithm")

        if item.payload_bytes not in PAYLOAD_SIZES:
            raise ValueError("unsupported payload size")

        expected_digest = PROFILES[item.algorithm].digest_bytes

        if item.digest_bytes != expected_digest:
            raise ValueError("incorrect digest length")

        if item.repeats != repeat_count(item.payload_bytes):
            raise ValueError("incorrect repeat count")

        expected_throughput = (
            item.payload_bytes
            * 1_000_000_000
            / item.median_ns
            / (1024 * 1024)
        )

        if not math.isclose(
            item.throughput_mib_s,
            expected_throughput,
            rel_tol=0.01,
            abs_tol=1e-9,
        ):
            raise ValueError("incorrect throughput")

    if actual_results != expected_results:
        raise ValueError("incomplete performance matrix")

    # Validate avalanche results.
    actual_avalanche = set()

    for item in report.avalanche:
        algorithm = item.algorithm

        if algorithm in actual_avalanche:
            raise ValueError("duplicate avalanche result")

        actual_avalanche.add(algorithm)

        if algorithm not in available:
            raise ValueError("avalanche result for unavailable algorithm")

        digest_bits = PROFILES[algorithm].digest_bytes * 8

        if item.digest_bits != digest_bits:
            raise ValueError("incorrect digest bit count")

        if item.min_flipped_bits > item.max_flipped_bits:
            raise ValueError("invalid avalanche bounds")

        if item.max_flipped_bits > digest_bits:
            raise ValueError("avalanche value exceeds digest length")

        if not (
            item.min_flipped_bits
            <= item.mean_flipped_bits
            <= item.max_flipped_bits
        ):
            raise ValueError("invalid avalanche mean")

        expected_fraction = item.mean_flipped_bits / digest_bits

        if not math.isclose(
            item.mean_fraction,
            expected_fraction,
            rel_tol=1e-9,
            abs_tol=1e-9,
        ):
            raise ValueError("incorrect avalanche fraction")

    if actual_avalanche != available:
        raise ValueError("incomplete avalanche coverage")

    # Validate correctness checks.
    actual_checks = set()

    for item in report.checks:
        key = (item.algorithm, item.name)

        if key in actual_checks:
            raise ValueError("duplicate correctness check")

        actual_checks.add(key)

        if item.algorithm not in available:
            raise ValueError("check for unavailable algorithm")

    expected_checks = {
        (algorithm, name)
        for algorithm in available
        for name in CHECK_NAMES
    }

    if actual_checks != expected_checks:
        raise ValueError("incomplete correctness checks")

    return report
