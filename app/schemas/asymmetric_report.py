
"""Strict structural and semantic validation for the asymmetric benchmark report."""

from datetime import datetime, timezone
from math import isclose
from typing import Annotated, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field


HYBRID_SIZES = [1024, 65536, 1048576]
DIRECT_SIZE = 64

PROFILE_CONFIG = {
    "rsa2048-oaep": {
        "group": "direct",
        "key_profile": "rsa-2048",
        "sizes": [64],
        "overhead": 0,
    },
    "rsa3072-oaep": {
        "group": "direct",
        "key_profile": "rsa-3072",
        "sizes": [64],
        "overhead": 0,
    },
    "rsa3072-oaep-aes256gcm": {
        "group": "hybrid",
        "key_profile": "rsa-3072",
        "sizes": HYBRID_SIZES,
        "overhead": 412,
    },
    "hpke-x25519-aes256gcm": {
        "group": "hybrid",
        "key_profile": "x25519",
        "sizes": HYBRID_SIZES,
        "overhead": 48,
    },
    "hpke-p256-aes256gcm": {
        "group": "hybrid",
        "key_profile": "p256",
        "sizes": HYBRID_SIZES,
        "overhead": 81,
    },
}

CHECK_NAMES = {
    "roundtrip",
    "wrong_key",
    "tamper",
    "wrong_context",
}

RSA_CHECK_NAMES = CHECK_NAMES | {"oaep_boundary"}


def _exact_integer(value: object) -> int:
    if type(value) is not int:
        raise ValueError("an exact integer is required")
    return value


One = Annotated[Literal[1], BeforeValidator(_exact_integer)]
Five = Annotated[Literal[5], BeforeValidator(_exact_integer)]
Ten = Annotated[Literal[10], BeforeValidator(_exact_integer)]
Twenty = Annotated[Literal[20], BeforeValidator(_exact_integer)]
SixtyFour = Annotated[Literal[64], BeforeValidator(_exact_integer)]

ProfileId = Literal[
    "rsa2048-oaep",
    "rsa3072-oaep",
    "rsa3072-oaep-aes256gcm",
    "hpke-x25519-aes256gcm",
    "hpke-p256-aes256gcm",
]

KeyId = Literal["rsa-2048", "rsa-3072", "x25519", "p256"]

PositiveFloat = Annotated[float, Field(gt=0, allow_inf_nan=False)]
NonNegativeFloat = Annotated[float, Field(ge=0, allow_inf_nan=False)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Experiment(StrictModel):
    series: Five
    operations_per_series: Twenty
    warmup: Ten
    keygen_runs: Five
    direct_payload_bytes: SixtyFour
    hybrid_sizes_bytes: list[int]
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    created_at_utc: str = Field(min_length=20, max_length=40)


class Environment(StrictModel):
    python: str = Field(min_length=1, max_length=100)
    cryptography: Literal["48.0.1"]
    openssl: str = Field(min_length=1, max_length=150)
    os: str = Field(min_length=1, max_length=150)
    cpu: str = Field(min_length=1, max_length=200)


class KeyGeneration(StrictModel):
    key_profile: KeyId
    runs: Five
    median_ns: PositiveFloat
    iqr_ns: NonNegativeFloat
    public_key_der_bytes: int = Field(gt=0, le=4096)


class Result(StrictModel):
    profile: ProfileId
    group: Literal["direct", "hybrid"]
    operation: Literal["encrypt", "decrypt"]
    payload_bytes: int = Field(gt=0, le=1048576)
    series: Five
    operations_per_series: Twenty
    median_ns: PositiveFloat
    iqr_ns: NonNegativeFloat
    ciphertext_bytes: int = Field(gt=0, le=1048988)
    throughput_mib_s: PositiveFloat | None


class Check(StrictModel):
    profile: ProfileId
    name: Literal[
        "roundtrip",
        "wrong_key",
        "tamper",
        "wrong_context",
        "oaep_boundary",
    ]
    passed: bool


class BenchmarkReport(StrictModel):
    schema_version: One
    experiment: Experiment
    environment: Environment
    key_generation: list[KeyGeneration] = Field(min_length=4, max_length=4)
    results: list[Result] = Field(min_length=22, max_length=22)
    checks: list[Check] = Field(min_length=22, max_length=22)


class BenchmarkResponse(BenchmarkReport):
    # The complete report is validated before filtering.
    # The filtered response may contain zero results.
    results: list[Result] = Field(max_length=22)


def _validate_timestamp(value: str) -> None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("created_at_utc must be a valid ISO 8601 timestamp") from exc

    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError("created_at_utc must use UTC")


def _expected_ciphertext_bytes(profile: str, payload_bytes: int) -> int:
    config = PROFILE_CONFIG[profile]

    if config["group"] == "direct":
        if profile == "rsa2048-oaep":
            return 256
        return 384

    return payload_bytes + config["overhead"]


def _validate_key_generation(report: BenchmarkReport) -> None:
    expected_profiles = {"rsa-2048", "rsa-3072", "x25519", "p256"}
    actual_profiles = [item.key_profile for item in report.key_generation]

    if len(set(actual_profiles)) != 4 or set(actual_profiles) != expected_profiles:
        raise ValueError("key_generation must contain exactly four unique key profiles")

    for item in report.key_generation:
        if item.runs != 5:
            raise ValueError("each key-generation profile must have five runs")


def _validate_results(report: BenchmarkReport) -> None:
    expected = {
        (profile, size, operation)
        for profile, config in PROFILE_CONFIG.items()
        for size in config["sizes"]
        for operation in ("encrypt", "decrypt")
    }

    actual = set()

    for item in report.results:
        key = (item.profile, item.payload_bytes, item.operation)

        if key in actual:
            raise ValueError(f"duplicate benchmark result: {key}")

        actual.add(key)

        config = PROFILE_CONFIG[item.profile]

        if item.group != config["group"]:
            raise ValueError(f"incorrect group for profile {item.profile}")

        if item.payload_bytes not in config["sizes"]:
            raise ValueError(f"incorrect payload size for profile {item.profile}")

        if item.series != 5 or item.operations_per_series != 20:
            raise ValueError("each result must contain five series of twenty operations")

        expected_size = _expected_ciphertext_bytes(
            item.profile,
            item.payload_bytes,
        )

        if item.ciphertext_bytes != expected_size:
            raise ValueError(
                f"incorrect ciphertext size for {item.profile}: "
                f"expected {expected_size}, got {item.ciphertext_bytes}"
            )

        if config["group"] == "direct":
            if item.throughput_mib_s is not None:
                raise ValueError("direct RSA results must have null throughput")
        else:
            expected_throughput = (
                item.payload_bytes
                / item.median_ns
                * 1_000_000_000
                / (1024 * 1024)
            )

            if item.throughput_mib_s is None or not isclose(
                item.throughput_mib_s,
                expected_throughput,
                rel_tol=0.02,
            ):
                raise ValueError(
                    f"incorrect throughput for {item.profile}, "
                    f"{item.payload_bytes} bytes, {item.operation}"
                )

    if actual != expected:
        missing = expected - actual
        extra = actual - expected
        raise ValueError(
            f"benchmark result coverage mismatch; missing={missing}, extra={extra}"
        )


def _validate_checks(report: BenchmarkReport) -> None:
    expected = set()

    for profile in PROFILE_CONFIG:
        names = RSA_CHECK_NAMES if profile.startswith("rsa") else CHECK_NAMES
        for name in names:
            expected.add((profile, name))

    actual = set()

    for item in report.checks:
        key = (item.profile, item.name)

        if key in actual:
            raise ValueError(f"duplicate check: {key}")

        actual.add(key)

    if actual != expected:
        missing = expected - actual
        extra = actual - expected
        raise ValueError(
            f"check coverage mismatch; missing={missing}, extra={extra}"
        )


def validate_complete_report(data: object) -> BenchmarkReport:
    report = BenchmarkReport.model_validate(data)

    if report.experiment.hybrid_sizes_bytes != HYBRID_SIZES:
        raise ValueError("hybrid_sizes_bytes must match the required sizes")

    _validate_timestamp(report.experiment.created_at_utc)
    _validate_key_generation(report)
    _validate_results(report)
    _validate_checks(report)

    # Failed checks remain in the report as evidence.
    # The validator does not silently change their passed values.
    return report
