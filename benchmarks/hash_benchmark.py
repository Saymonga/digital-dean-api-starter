
"""Reproducible hashing benchmark and avalanche experiment."""

import csv
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, median, quantiles
from time import perf_counter_ns

from app.security.hashing.adapters import (
    hash_bytes,
    hamming_bits,
    prepare_operation,
)
from app.security.hashing.profiles import (
    AVALANCHE_BYTES,
    AVALANCHE_TRIALS,
    CHECK_NAMES,
    CHUNK_BYTES,
    PAYLOAD_SIZES,
    PROFILES,
    SERIES,
    WARMUP,
    make_hasher,
    probe_profiles,
    repeat_count,
    synthetic_payload,
)
from app.schemas.hash_report import validate_report


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "results" / "practice-04"

RAW_COLUMNS = [
    "algorithm",
    "mode",
    "payload_bytes",
    "series",
    "repeats",
    "elapsed_ns",
    "ns_per_op",
]

AVALANCHE_COLUMNS = [
    "algorithm",
    "trial",
    "bit_index",
    "digest_bits",
    "flipped_bits",
    "fraction",
]

KNOWN_ABC = {
    "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "sha512": "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    "sha3-256": "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    "blake2b-256": "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
    "blake2s-256": "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
    "md5": "900150983cd24fb0d6963f7d28e17f72",
    "sha1": "a9993e364706816aba3e25717850c26c9cd0d89d",
}

KNOWN_EMPTY = {
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "sha512": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    "sha3-256": "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
    "blake2b-256": "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
    "blake2s-256": "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
}


def get_source_commit() -> str:
    """Require a clean Git tree and record the source revision."""
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )

    if status.stdout.strip():
        raise RuntimeError(
            "Working tree must be clean before the experiment. "
            "Commit source changes first."
        )

    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def environment_info() -> dict:
    """Collect reproducibility metadata."""
    return {
        "python": sys.version.split()[0],
        "openssl_ssl": getattr(
            __import__("ssl"), "OPENSSL_VERSION", "unknown"
        ),
        "os": platform.platform(),
        "cpu": platform.processor() or platform.machine() or "unknown",
        "architecture": platform.machine() or "unknown",
    }


def correctness_checks(algorithm: str) -> list[dict]:
    """Run six independent correctness checks."""
    checks = []

    def add(name: str, passed: bool):
        checks.append({
            "algorithm": algorithm,
            "name": name,
            "passed": bool(passed),
        })

    add(
        "known-abc",
        hash_bytes(algorithm, b"abc").hex() == KNOWN_ABC[algorithm],
    )

    add(
        "known-empty",
        hash_bytes(algorithm, b"").hex() == KNOWN_EMPTY[algorithm],
    )

    unicode_data = "Цифровий деканат — тест UTF-8".encode("utf-8")
    first = hash_bytes(algorithm, unicode_data)
    second = hash_bytes(algorithm, unicode_data)

    add("unicode-utf8", first == second)

    add(
        "determinism",
        hash_bytes(algorithm, b"repeatable") ==
        hash_bytes(algorithm, b"repeatable"),
    )

    add(
        "digest-length",
        len(hash_bytes(algorithm, b"digest")) ==
        PROFILES[algorithm].digest_bytes,
    )

    payload = synthetic_payload(16385)

    whole = hash_bytes(algorithm, payload, "whole")
    chunked = hash_bytes(algorithm, payload, "chunked")

    add("stream-equivalence", whole == chunked)

    return checks


def measure(
    operation,
    repeats: int,
) -> tuple[int, float]:
    """Measure one batch and return elapsed nanoseconds and ns per operation."""
    start = perf_counter_ns()

    for _ in range(repeats):
        operation()

    elapsed = perf_counter_ns() - start

    return elapsed, elapsed / repeats


def measure_performance(available: list[str]):
    """Run warmups and five measurement series for every combination."""
    raw_rows = []
    results = []

    for algorithm in available:
        for mode in ("whole", "chunked"):
            for size in PAYLOAD_SIZES:
                payload = synthetic_payload(size)
                operation = prepare_operation(algorithm, payload, mode)
                repeats = repeat_count(size)

                for _ in range(WARMUP):
                    operation()

                series_means = []

                for series_number in range(1, SERIES + 1):
                    elapsed_ns, ns_per_op = measure(
                        operation,
                        repeats,
                    )

                    series_means.append(ns_per_op)

                    raw_rows.append({
                        "algorithm": algorithm,
                        "mode": mode,
                        "payload_bytes": size,
                        "series": series_number,
                        "repeats": repeats,
                        "elapsed_ns": elapsed_ns,
                        "ns_per_op": ns_per_op,
                    })

                q1, _, q3 = quantiles(
                    series_means,
                    n=4,
                    method="inclusive",
                )

                typical = median(series_means)

                results.append({
                    "algorithm": algorithm,
                    "mode": mode,
                    "payload_bytes": size,
                    "digest_bytes": PROFILES[algorithm].digest_bytes,
                    "repeats": repeats,
                    "median_ns": typical,
                    "iqr_ns": q3 - q1,
                    "throughput_mib_s": (
                        size * 1_000_000_000
                        / typical
                        / (1024 * 1024)
                    ),
                })

                print(
                    f"Measured {algorithm:12s} "
                    f"{mode:7s} {size:8d} bytes"
                )

    return raw_rows, results


def avalanche_experiment(available: list[str]):
    """Perform 100 independent one-bit changes for each algorithm."""
    payload = synthetic_payload(AVALANCHE_BYTES)

    raw_rows = []
    aggregates = []

    for algorithm in available:
        original_digest = hash_bytes(algorithm, payload)
        digest_bits = len(original_digest) * 8
        distances = []

        for trial in range(AVALANCHE_TRIALS):
            changed = bytearray(payload)

            byte_index = trial // 8
            bit_position = trial % 8

            changed[byte_index] ^= 1 << bit_position

            changed_digest = hash_bytes(
                algorithm,
                bytes(changed),
            )

            distance = hamming_bits(
                original_digest,
                changed_digest,
            )

            fraction = distance / digest_bits
            distances.append(distance)

            raw_rows.append({
                "algorithm": algorithm,
                "trial": trial + 1,
                "bit_index": trial,
                "digest_bits": digest_bits,
                "flipped_bits": distance,
                "fraction": fraction,
            })

        aggregates.append({
            "algorithm": algorithm,
            "input_bytes": AVALANCHE_BYTES,
            "trials": AVALANCHE_TRIALS,
            "digest_bits": digest_bits,
            "min_flipped_bits": min(distances),
            "max_flipped_bits": max(distances),
            "mean_flipped_bits": mean(distances),
            "mean_fraction": mean(distances) / digest_bits,
        })

        print(f"Avalanche complete: {algorithm}")

    return raw_rows, aggregates


def write_csv(path: Path, columns: list[str], rows: list[dict]):
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def create_charts(results: list[dict], avalanche: list[dict]):
    """Create throughput and avalanche charts."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    OUTPUT.mkdir(parents=True, exist_ok=True)

    algorithms = list(PROFILES)

    plt.figure(figsize=(12, 7))

    for algorithm in algorithms:
        values = [
            item["throughput_mib_s"]
            for item in results
            if item["algorithm"] == algorithm
            and item["mode"] == "whole"
        ]

        if values:
            sizes = [
                item["payload_bytes"]
                for item in results
                if item["algorithm"] == algorithm
                and item["mode"] == "whole"
            ]
            plt.plot(sizes, values, marker="o", label=algorithm)

    plt.xscale("log")
    plt.yscale("log")
    plt.xlabel("Payload size (bytes)")
    plt.ylabel("Throughput (MiB/s)")
    plt.title("Hash algorithm throughput — whole mode")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.savefig(OUTPUT / "chart_throughput.png", dpi=160)
    plt.close()

    plt.figure(figsize=(12, 7))

    names = [item["algorithm"] for item in avalanche]
    fractions = [item["mean_fraction"] for item in avalanche]

    plt.bar(names, fractions)
    plt.axhline(0.5, linestyle="--", label="50% reference")
    plt.ylabel("Mean fraction of flipped digest bits")
    plt.title("Avalanche effect by hash algorithm")
    plt.ylim(0, 1)
    plt.xticks(rotation=25, ha="right")
    plt.legend()
    plt.tight_layout()
    plt.savefig(OUTPUT / "chart_avalanche.png", dpi=160)
    plt.close()


def run_experiment() -> None:
    """Run the complete local experiment and save validated artifacts."""
    source_commit = get_source_commit()

    OUTPUT.mkdir(parents=True, exist_ok=True)

    statuses = probe_profiles()
    available = [
        item["algorithm"]
        for item in statuses
        if item["available"]
    ]

    if len(available) < 5:
        raise RuntimeError("Fewer than five hash profiles are available")

    print("Available profiles:", ", ".join(available))
    print("Starting performance measurements...")

    raw_rows, results = measure_performance(available)

    print("Starting avalanche experiment...")
    avalanche_rows, avalanche = avalanche_experiment(available)

    checks = []

    for algorithm in available:
        checks.extend(correctness_checks(algorithm))

    write_csv(
        OUTPUT / "raw.csv",
        RAW_COLUMNS,
        raw_rows,
    )

    write_csv(
        OUTPUT / "avalanche.csv",
        AVALANCHE_COLUMNS,
        avalanche_rows,
    )

    report = {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat().replace(
            "+00:00", "Z"
        ),
        "source_commit": source_commit,
        "parameters": {
            "sizes": list(PAYLOAD_SIZES),
            "chunk_bytes": CHUNK_BYTES,
            "warmup": WARMUP,
            "series": SERIES,
            "repeats_small": 1000,
            "repeats_large": 100,
            "avalanche_trials": AVALANCHE_TRIALS,
            "avalanche_bytes": AVALANCHE_BYTES,
        },
        "environment": environment_info(),
        "algorithms": statuses,
        "results": results,
        "avalanche": avalanche,
        "checks": checks,
    }

    # Validate the complete report before writing it.
    validated = validate_report(report)

    report_path = OUTPUT / "report.json"

    with report_path.open("w", encoding="utf-8") as stream:
        json.dump(
            validated.model_dump(mode="json"),
            stream,
            ensure_ascii=False,
            indent=2,
            allow_nan=False,
        )

    create_charts(results, avalanche)

    failed_checks = [item for item in checks if not item["passed"]]

    print("\nExperiment completed.")
    print("Source commit:", source_commit)
    print("Performance rows:", len(raw_rows))
    print("Aggregated results:", len(results))
    print("Avalanche rows:", len(avalanche_rows))
    print("Avalanche aggregates:", len(avalanche))
    print("Correctness checks:", len(checks))
    print("Failed checks:", len(failed_checks))
    print("Output directory:", OUTPUT)

    if failed_checks:
        for item in failed_checks:
            print("FAILED:", item)
        raise SystemExit(1)


if __name__ == "__main__":
    run_experiment()
