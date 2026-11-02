
"""Вимірювання AES-GCM та ChaCha20-Poly1305 для двох бібліотек."""

import argparse
import csv
import json
import platform
import ssl
import statistics
import sys
import time
from importlib.metadata import version
from pathlib import Path
from secrets import token_bytes
from uuid import uuid4

from app.security.adapters import seal_bytes, open_bytes
from app.security.profiles import BACKENDS, KEY_BYTES


SIZES_BYTES = (1024, 65536, 1048576)
WARMUP = 10
SERIES = 5
OPERATIONS_PER_SERIES = 100
BENCHMARK_AAD = b"digital-dean-practice-02-benchmark".ljust(64, b".")

ALGORITHMS = tuple(KEY_BYTES.keys())
NONCE_BYTES = 12
TAG_BYTES = 16


def measure_batch(operation, arguments) -> float:
    """Повернути середній час однієї операції в наносекундах."""
    if not arguments:
        raise ValueError("Batch must contain at least one operation")

    started = time.perf_counter_ns()

    for args in arguments:
        operation(*args)

    elapsed = time.perf_counter_ns() - started
    return elapsed / len(arguments)


def summarize(series_mean_ns, size_bytes) -> dict:
    """Обчислити медіану, inclusive IQR та пропускну здатність."""
    if len(series_mean_ns) != SERIES:
        raise ValueError("Expected exactly five measurement series")

    if any(value <= 0 for value in series_mean_ns):
        raise ValueError("Measurement values must be positive")

    median_ns = statistics.median(series_mean_ns)
    quartiles = statistics.quantiles(
        series_mean_ns,
        n=4,
        method="inclusive",
    )
    iqr_ns = quartiles[2] - quartiles[0]

    throughput_mib_s = (
        size_bytes * 1_000_000_000
        / ((2 ** 20) * median_ns)
    )

    return {
        "series_mean_ns": series_mean_ns,
        "median_ns": median_ns,
        "iqr_ns": iqr_ns,
        "throughput_mib_s": throughput_mib_s,
    }


def _make_nonce(counter: int) -> bytes:
    """Створити унікальний 12-байтовий nonce."""
    if counter >= 2 ** (NONCE_BYTES * 8):
        raise RuntimeError("Nonce counter exhausted")
    return counter.to_bytes(NONCE_BYTES, byteorder="big")


def _prepare_encrypt_arguments(
    backend,
    algorithm,
    key,
    data,
    count,
    nonce_start,
):
    """Підготувати аргументи шифрування поза вимірюванням."""
    operation = lambda k, n, d, aad: seal_bytes(
        backend, algorithm, k, n, d, aad
    )

    arguments = [
        (key, _make_nonce(nonce_start + index), data, BENCHMARK_AAD)
        for index in range(count)
    ]

    return operation, arguments


def _prepare_decrypt_arguments(
    backend,
    algorithm,
    key,
    data,
    count,
    nonce_start,
):
    """Зашифрувати тестові дані поза таймером для вимірювання розшифрування."""
    arguments = []

    for index in range(count):
        nonce = _make_nonce(nonce_start + index)

        ciphertext, tag = seal_bytes(
            backend,
            algorithm,
            key,
            nonce,
            data,
            BENCHMARK_AAD,
        )

        arguments.append(
            (
                key,
                nonce,
                ciphertext,
                tag,
                BENCHMARK_AAD,
            )
        )

    operation = lambda k, n, ct, tag, aad: open_bytes(
        backend, algorithm, k, n, ct, tag, aad
    )

    return operation, arguments


def _measure_with_details(operation, arguments):
    """Повернути фактичний сумарний та середній час серії."""
    started = time.perf_counter_ns()

    for args in arguments:
        operation(*args)

    total_ns = time.perf_counter_ns() - started
    mean_ns = total_ns / len(arguments)

    return total_ns, mean_ns


def _environment() -> dict:
    """Зібрати інформацію про середовище експерименту."""
    try:
        cpu_model = platform.processor() or "Unknown"
    except Exception:
        cpu_model = "Unknown"

    return {
        "cpu_model": cpu_model,
        "os": platform.platform(),
        "architecture": platform.machine(),
        "python_version": sys.version,
        "library_versions": {
            "cryptography": version("cryptography"),
            "pycryptodome": version("pycryptodome"),
        },
        "openssl_version": ssl.OPENSSL_VERSION,
        "crypto_acceleration": (
            "Використання апаратного прискорення визначається "
            "криптографічними бібліотеками; окреме вимірювання "
            "апаратного прискорення не виконувалося."
        ),
    }


def run_benchmark(output_dir: Path) -> None:
    """Виконати експеримент та зберегти raw.csv і report.json."""
    output_dir.mkdir(parents=True, exist_ok=True)

    run_id = str(uuid4())
    raw_rows = []
    results = []

    for backend in BACKENDS:
        for algorithm in ALGORITHMS:
            key = token_bytes(KEY_BYTES[algorithm])

            # Один лічильник nonce на комбінацію ключа,
            # алгоритму та бібліотеки.
            nonce_counter = 0

            for size_bytes in SIZES_BYTES:
                data = token_bytes(size_bytes)

                for operation_name in ("encrypt", "decrypt"):
                    series_means = []

                    for series_index in range(1, SERIES + 1):
                        if operation_name == "encrypt":
                            operation, warmup_arguments = (
                                _prepare_encrypt_arguments(
                                    backend,
                                    algorithm,
                                    key,
                                    data,
                                    WARMUP,
                                    nonce_counter,
                                )
                            )
                            nonce_counter += WARMUP

                            measure_batch(operation, warmup_arguments)

                            operation, arguments = (
                                _prepare_encrypt_arguments(
                                    backend,
                                    algorithm,
                                    key,
                                    data,
                                    OPERATIONS_PER_SERIES,
                                    nonce_counter,
                                )
                            )
                            nonce_counter += OPERATIONS_PER_SERIES

                        else:
                            operation, warmup_arguments = (
                                _prepare_decrypt_arguments(
                                    backend,
                                    algorithm,
                                    key,
                                    data,
                                    WARMUP,
                                    nonce_counter,
                                )
                            )
                            nonce_counter += WARMUP

                            measure_batch(operation, warmup_arguments)

                            operation, arguments = (
                                _prepare_decrypt_arguments(
                                    backend,
                                    algorithm,
                                    key,
                                    data,
                                    OPERATIONS_PER_SERIES,
                                    nonce_counter,
                                )
                            )
                            nonce_counter += OPERATIONS_PER_SERIES

                        total_ns, mean_ns = _measure_with_details(
                            operation,
                            arguments,
                        )

                        series_means.append(mean_ns)

                        raw_rows.append({
                            "run_id": run_id,
                            "backend": backend,
                            "algorithm": algorithm,
                            "size_bytes": size_bytes,
                            "operation": operation_name,
                            "series_index": series_index,
                            "operations": OPERATIONS_PER_SERIES,
                            "total_ns": total_ns,
                            "mean_ns": mean_ns,
                        })

                        print(
                            f"{backend:12} {algorithm:20} "
                            f"{size_bytes:8} bytes "
                            f"{operation_name:7} "
                            f"series {series_index}/{SERIES}: "
                            f"{mean_ns:.2f} ns/op"
                        )

                    summary = summarize(series_means, size_bytes)

                    results.append({
                        "backend": backend,
                        "algorithm": algorithm,
                        "size_bytes": size_bytes,
                        "operation": operation_name,
                        **summary,
                    })

    raw_path = output_dir / "raw.csv"

    fieldnames = [
        "run_id",
        "backend",
        "algorithm",
        "size_bytes",
        "operation",
        "series_index",
        "operations",
        "total_ns",
        "mean_ns",
    ]

    with raw_path.open(
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(raw_rows)

    report = {
        "schema_version": 1,
        "run_id": run_id,
        "environment": _environment(),
        "parameters": {
            "sizes_bytes": list(SIZES_BYTES),
            "warmup": WARMUP,
            "series": SERIES,
            "operations_per_series": OPERATIONS_PER_SERIES,
            "context_bytes": len(BENCHMARK_AAD),
            "include_cipher_object_creation": True,
        },
        "results": results,
    }

    report_path = output_dir / "report.json"

    report_path.write_text(
        json.dumps(
            report,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    assert len(raw_rows) == 180
    assert len(results) == 36

    print("\nЕксперимент завершено.")
    print(f"Raw measurements: {raw_path}")
    print(f"Aggregated report: {report_path}")
    print(f"Raw rows: {len(raw_rows)}")
    print(f"Aggregated results: {len(results)}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Practice 2 symmetric cryptographic benchmark"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
    )

    args = parser.parse_args()

    run_benchmark(args.output_dir)


if __name__ == "__main__":
    main()
