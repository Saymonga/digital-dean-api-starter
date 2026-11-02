
"""Побудова графіків за фактичними результатами бенчмарку."""

import json
from pathlib import Path

import matplotlib.pyplot as plt


BASE_DIR = Path(__file__).resolve().parents[1]
REPORT_PATH = BASE_DIR / "results" / "practice-02" / "report.json"
OUTPUT_DIR = BASE_DIR / "results" / "practice-02"


def main():
    report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    results = report["results"]

    algorithms = (
        "AES-128-GCM",
        "AES-256-GCM",
        "ChaCha20-Poly1305",
    )

    sizes = (1024, 65536, 1048576)

    # Графік 1. Пропускна здатність для шести комбінацій.
    fig, ax = plt.subplots(figsize=(12, 7))

    labels = []
    values = []

    for backend in ("cryptography", "pycryptodome"):
        for algorithm in algorithms:
            for size in sizes:
                row = next(
                    r for r in results
                    if r["backend"] == backend
                    and r["algorithm"] == algorithm
                    and r["size_bytes"] == size
                    and r["operation"] == "encrypt"
                )

                labels.append(
                    f"{backend}\n{algorithm}\n{size // 1024} KiB"
                )
                values.append(row["throughput_mib_s"])

    ax.bar(range(len(values)), values)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=55, ha="right", fontsize=8)
    ax.set_ylabel("Throughput (MiB/s)")
    ax.set_title("Encryption throughput comparison")
    ax.grid(axis="y", alpha=0.3)

    fig.tight_layout()
    fig.savefig(
        OUTPUT_DIR / "chart_throughput.png",
        dpi=200,
    )
    plt.close(fig)

    # Графік 2. Час шифрування та розшифрування залежно від розміру.
    fig, ax = plt.subplots(figsize=(12, 7))

    for backend in ("cryptography", "pycryptodome"):
        for algorithm in algorithms:
            for operation in ("encrypt", "decrypt"):
                selected = [
                    r for r in results
                    if r["backend"] == backend
                    and r["algorithm"] == algorithm
                    and r["operation"] == operation
                ]

                selected.sort(key=lambda r: r["size_bytes"])

                x = [
                    r["size_bytes"] / 1024
                    for r in selected
                ]
                y = [
                    r["median_ns"] / 1_000_000
                    for r in selected
                ]

                ax.plot(
                    x,
                    y,
                    marker="o",
                    label=f"{backend} | {algorithm} | {operation}",
                )

    ax.set_xscale("log", base=2)
    ax.set_xlabel("Data size (KiB)")
    ax.set_ylabel("Median time (ms)")
    ax.set_title("Encryption and decryption time")
    ax.set_xticks([1, 64, 1024])
    ax.set_xticklabels(["1", "64", "1024"])
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=7, loc="upper left")

    fig.tight_layout()
    fig.savefig(
        OUTPUT_DIR / "chart_operation_time.png",
        dpi=200,
    )
    plt.close(fig)

    print("Графіки успішно створено:")
    print(OUTPUT_DIR / "chart_throughput.png")
    print(OUTPUT_DIR / "chart_operation_time.png")


if __name__ == "__main__":
    main()
