
"""Reproducible offline benchmark for asymmetric cryptography profiles."""

import csv
import json
import platform
import secrets
import statistics
import subprocess
import sys

from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter_ns

import cryptography
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends.openssl.backend import backend

from app.security.asymmetric.adapters import (
    DecryptionError,
    decrypt,
    encrypt,
    generate_keypair,
)
from app.security.asymmetric.profiles import (
    CONTEXT,
    PROFILES,
    HYBRID_SIZES,
    oaep_max_bytes,
)
from app.schemas.asymmetric_report import validate_complete_report


BASE_DIR = Path(__file__).resolve().parents[1]
OUTPUT_DIR = BASE_DIR / "results" / "practice-03"
CSV_PATH = OUTPUT_DIR / "raw.csv"
REPORT_PATH = OUTPUT_DIR / "report.json"

SERIES = 5
OPERATIONS = 20
WARMUP = 10
KEYGEN_RUNS = 5

MIB = 1024 * 1024

CSV_COLUMNS = (
    "group",
    "profile",
    "operation",
    "payload_bytes",
    "series_index",
    "operations",
    "elapsed_ns",
    "ns_per_operation",
    "ciphertext_bytes",
)


def summarize(samples: list[float]) -> tuple[float, float]:
    """Return median and inclusive interquartile range."""
    if len(samples) != SERIES:
        raise ValueError("five series required")

    q1, _, q3 = statistics.quantiles(
        samples,
        n=4,
        method="inclusive",
    )

    return float(statistics.median(samples)), float(q3 - q1)


def source_commit() -> str:
    """Read the current Git commit before the experiment."""
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=BASE_DIR,
        check=True,
        capture_output=True,
        text=True,
    )

    commit = result.stdout.strip()

    if len(commit) != 40:
        raise RuntimeError("Could not determine the source commit")

    return commit


def public_key_der_size(public_key: object) -> int:
    """Measure public key size in DER SubjectPublicKeyInfo format."""
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return len(der)


def make_raw_row(
    group: str,
    profile: str,
    operation: str,
    payload_bytes: int,
    series_index: int,
    elapsed_ns: int,
    operations: int,
    ciphertext_bytes: int,
) -> dict:
    return {
        "group": group,
        "profile": profile,
        "operation": operation,
        "payload_bytes": payload_bytes,
        "series_index": series_index,
        "operations": operations,
        "elapsed_ns": elapsed_ns,
        "ns_per_operation": elapsed_ns / operations,
        "ciphertext_bytes": ciphertext_bytes,
    }


def warmup(
    profile: str,
    public_key: object,
    private_key: object,
    payload_size: int,
) -> None:
    """Perform warmup operations outside measured intervals."""
    message = secrets.token_bytes(payload_size)

    envelopes = []

    for _ in range(WARMUP):
        envelopes.append(
            encrypt(profile, public_key, message)
        )

    for envelope in envelopes:
        plaintext = decrypt(profile, private_key, envelope)

        if plaintext != message:
            raise RuntimeError(
                f"Warmup roundtrip failed for {profile}"
            )


def measure_key_generation(
    raw_rows: list[dict],
) -> list[dict]:
    """Measure generation of four independent key profiles."""
    key_profiles = ("rsa-2048", "rsa-3072", "x25519", "p256")

    aggregates = []

    for key_profile in key_profiles:
        # Warmup is excluded from measurements.
        for _ in range(WARMUP):
            generate_keypair(key_profile)

        samples = []
        der_size = None

        for series_index in range(SERIES):
            started = perf_counter_ns()

            private_key, public_key = generate_keypair(key_profile)

            elapsed_ns = perf_counter_ns() - started

            # Serialization is intentionally outside the timer.
            current_der_size = public_key_der_size(public_key)

            if der_size is not None and current_der_size != der_size:
                raise RuntimeError("Public key DER size changed")

            der_size = current_der_size
            samples.append(elapsed_ns)

            raw_rows.append(
                make_raw_row(
                    group="key_generation",
                    profile=key_profile,
                    operation="generate",
                    payload_bytes=0,
                    series_index=series_index + 1,
                    elapsed_ns=elapsed_ns,
                    operations=1,
                    ciphertext_bytes=current_der_size,
                )
            )

        median_ns, iqr_ns = summarize(samples)

        aggregates.append(
            {
                "key_profile": key_profile,
                "runs": KEYGEN_RUNS,
                "median_ns": median_ns,
                "iqr_ns": iqr_ns,
                "public_key_der_bytes": der_size,
            }
        )

    return aggregates


def run_correctness_checks() -> list[dict]:
    """Run 22 correctness and rejection checks."""
    checks = []

    for profile, spec in PROFILES.items():
        private_key, public_key = generate_keypair(spec.key_profile)

        payload_size = spec.sizes[0]
        message = secrets.token_bytes(payload_size)

        envelope = encrypt(profile, public_key, message)

        # 1. Roundtrip.
        try:
            recovered = decrypt(profile, private_key, envelope)
            roundtrip_passed = recovered == message
        except DecryptionError:
            roundtrip_passed = False

        checks.append(
            {
                "profile": profile,
                "name": "roundtrip",
                "passed": roundtrip_passed,
            }
        )

        # 2. Wrong recipient key must reject the envelope.
        wrong_private, _ = generate_keypair(spec.key_profile)

        try:
            decrypt(profile, wrong_private, envelope)
            wrong_key_passed = False
        except DecryptionError:
            wrong_key_passed = True

        checks.append(
            {
                "profile": profile,
                "name": "wrong_key",
                "passed": wrong_key_passed,
            }
        )

        # 3. Modified ciphertext must be rejected.
        tampered = bytearray(envelope)
        tampered[-1] ^= 1

        try:
            decrypt(profile, private_key, bytes(tampered))
            tamper_passed = False
        except DecryptionError:
            tamper_passed = True

        checks.append(
            {
                "profile": profile,
                "name": "tamper",
                "passed": tamper_passed,
            }
        )

        # 4. Different context must be rejected.
        try:
            decrypt(
                profile,
                private_key,
                envelope,
                context=CONTEXT + b"-wrong",
            )
            context_passed = False
        except DecryptionError:
            context_passed = True

        checks.append(
            {
                "profile": profile,
                "name": "wrong_context",
                "passed": context_passed,
            }
        )

        # OAEP boundary checks apply only to direct RSA profiles.
        if profile in ("rsa2048-oaep", "rsa3072-oaep"):
            maximum = oaep_max_bytes(
                2048 if profile == "rsa2048-oaep" else 3072
            )

            try:
                boundary_envelope = encrypt(
                    profile,
                    public_key,
                    b"A" * maximum,
                )

                boundary_accepted = len(boundary_envelope) > 0

                try:
                    encrypt(
                        profile,
                        public_key,
                        b"A" * (maximum + 1),
                    )
                    oversized_rejected = False
                except ValueError:
                    oversized_rejected = True

                boundary_passed = (
                    boundary_accepted and oversized_rejected
                )

            except (ValueError, DecryptionError):
                boundary_passed = False

            checks.append(
                {
                    "profile": profile,
                    "name": "oaep_boundary",
                    "passed": boundary_passed,
                }
            )

    if len(checks) != 22:
        raise RuntimeError(
            f"Expected 22 correctness checks, got {len(checks)}"
        )

    return checks


def measure_operations(
    keypairs: dict,
    raw_rows: list[dict],
) -> list[dict]:
    """Measure encryption and decryption for all required combinations."""
    samples = {}

    ciphertext_sizes = {}

    tasks = [
        (profile, size)
        for profile, spec in PROFILES.items()
        for size in spec.sizes
    ]

    # Warmup every profile and payload size before measurement.
    for profile, size in tasks:
        private_key, public_key = keypairs[profile]

        warmup(
            profile,
            public_key,
            private_key,
            size,
        )

    # Five series, with profile order rotated between series.
    for series_index in range(SERIES):
        shift = series_index % len(tasks)
        ordered_tasks = tasks[shift:] + tasks[:shift]

        for profile, size in ordered_tasks:
            private_key, public_key = keypairs[profile]
            message = secrets.token_bytes(size)

            key = (profile, size)

            # Encryption: output envelopes are collected inside the timer.
            started = perf_counter_ns()

            envelopes = [
                encrypt(profile, public_key, message)
                for _ in range(OPERATIONS)
            ]

            elapsed_ns = perf_counter_ns() - started

            ns_per_operation = elapsed_ns / OPERATIONS

            samples.setdefault(
                (profile, size, "encrypt"),
                [],
            ).append(ns_per_operation)

            ciphertext_size = len(envelopes[0])

            if any(len(item) != ciphertext_size for item in envelopes):
                raise RuntimeError("Ciphertext sizes are inconsistent")

            ciphertext_sizes[key] = ciphertext_size

            # Verify encryption outputs outside the timer.
            for envelope in envelopes:
                if decrypt(profile, private_key, envelope) != message:
                    raise RuntimeError(
                        f"Encryption verification failed: {profile}"
                    )

            raw_rows.append(
                make_raw_row(
                    group=PROFILES[profile].group,
                    profile=profile,
                    operation="encrypt",
                    payload_bytes=size,
                    series_index=series_index + 1,
                    elapsed_ns=elapsed_ns,
                    operations=OPERATIONS,
                    ciphertext_bytes=ciphertext_size,
                )
            )

            # Decryption envelopes are prepared before timing.
            decrypt_envelopes = [
                encrypt(profile, public_key, message)
                for _ in range(OPERATIONS)
            ]

            started = perf_counter_ns()

            plaintexts = [
                decrypt(profile, private_key, envelope)
                for envelope in decrypt_envelopes
            ]

            elapsed_ns = perf_counter_ns() - started

            ns_per_operation = elapsed_ns / OPERATIONS

            samples.setdefault(
                (profile, size, "decrypt"),
                [],
            ).append(ns_per_operation)

            # Verify plaintext outside the timer.
            if any(plaintext != message for plaintext in plaintexts):
                raise RuntimeError(
                    f"Decryption verification failed: {profile}"
                )

            raw_rows.append(
                make_raw_row(
                    group=PROFILES[profile].group,
                    profile=profile,
                    operation="decrypt",
                    payload_bytes=size,
                    series_index=series_index + 1,
                    elapsed_ns=elapsed_ns,
                    operations=OPERATIONS,
                    ciphertext_bytes=len(decrypt_envelopes[0]),
                )
            )

    results = []

    for profile, spec in PROFILES.items():
        for size in spec.sizes:
            for operation in ("encrypt", "decrypt"):
                values = samples[(profile, size, operation)]

                median_ns, iqr_ns = summarize(values)

                if spec.group == "hybrid":
                    throughput = (
                        size
                        / median_ns
                        * 1_000_000_000
                        / MIB
                    )
                else:
                    throughput = None

                results.append(
                    {
                        "profile": profile,
                        "group": spec.group,
                        "operation": operation,
                        "payload_bytes": size,
                        "series": SERIES,
                        "operations_per_series": OPERATIONS,
                        "median_ns": median_ns,
                        "iqr_ns": iqr_ns,
                        "ciphertext_bytes": ciphertext_sizes[
                            (profile, size)
                        ],
                        "throughput_mib_s": throughput,
                    }
                )

    if len(results) != 22:
        raise RuntimeError(
            f"Expected 22 aggregate results, got {len(results)}"
        )

    return results


def write_csv(raw_rows: list[dict]) -> None:
    """Write all raw measurements to CSV."""
    if len(raw_rows) != 130:
        raise RuntimeError(
            f"Expected 130 raw rows, got {len(raw_rows)}"
        )

    with CSV_PATH.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=CSV_COLUMNS,
        )

        writer.writeheader()
        writer.writerows(raw_rows)


def environment_metadata() -> dict:
    """Collect reproducibility metadata."""
    return {
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
        "openssl": backend.openssl_version_text(),
        "os": platform.platform(),
        "cpu": platform.processor() or platform.machine() or "unknown",
    }


def run_experiment() -> None:
    """Execute the complete offline experiment and save validated results."""
    if cryptography.__version__ != "48.0.1":
        raise RuntimeError(
            "This experiment requires cryptography==48.0.1"
        )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    commit = source_commit()

    print("Starting asymmetric cryptography benchmark...")
    print(f"Source commit: {commit}")
    print(f"Python: {platform.python_version()}")
    print(f"cryptography: {cryptography.__version__}")

    raw_rows = []

    # Generate one recipient keypair per profile outside operation timers.
    keypairs = {}

    for profile, spec in PROFILES.items():
        keypairs[profile] = generate_keypair(spec.key_profile)

    print("Measuring key generation...")
    key_generation = measure_key_generation(raw_rows)

    print("Measuring encryption and decryption...")
    results = measure_operations(
        keypairs,
        raw_rows,
    )

    print("Running correctness checks...")
    checks = run_correctness_checks()

    experiment = {
        "series": SERIES,
        "operations_per_series": OPERATIONS,
        "warmup": WARMUP,
        "keygen_runs": KEYGEN_RUNS,
        "direct_payload_bytes": 64,
        "hybrid_sizes_bytes": list(HYBRID_SIZES),
        "source_commit": commit,
        "created_at_utc": (
            datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        ),
    }

    report_data = {
        "schema_version": 1,
        "experiment": experiment,
        "environment": environment_metadata(),
        "key_generation": key_generation,
        "results": results,
        "checks": checks,
    }

    # Validate the complete report before saving either artifact.
    report = validate_complete_report(report_data)

    write_csv(raw_rows)

    REPORT_PATH.write_text(
        json.dumps(
            report.model_dump(mode="json"),
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        ),
        encoding="utf-8",
    )

    failed_checks = [
        item
        for item in report.checks
        if not item.passed
    ]

    print()
    print("Benchmark completed.")
    print(f"Raw rows: {len(raw_rows)}")
    print(f"Key generation aggregates: {len(report.key_generation)}")
    print(f"Operation aggregates: {len(report.results)}")
    print(f"Correctness checks: {len(report.checks)}")
    print(f"Failed checks: {len(failed_checks)}")
    print(f"CSV: {CSV_PATH}")
    print(f"JSON: {REPORT_PATH}")

    if failed_checks:
        for item in failed_checks:
            print(
                f"FAILED: {item.profile} / {item.name}"
            )

        raise RuntimeError(
            "One or more correctness checks failed"
        )


def main() -> int:
    try:
        run_experiment()
    except Exception as exc:
        print(f"Benchmark failed: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
