"""Create charts for Practice 03 asymmetric cryptography benchmark."""

import json
from pathlib import Path

import matplotlib.pyplot as plt


BASE_DIR = Path(__file__).resolve().parents[1]
REPORT_PATH = BASE_DIR / "results" / "practice-03" / "report.json"
OUTPUT_DIR = BASE_DIR / "results" / "practice-03"


def main():
    report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    results = report["results"]

    profiles = (
        "rsa2048-oaep",
        "rsa3072-oaep",
        "rsa3072-oaep-aes256gcm",
        "hpke-x25519-aes256gcm",
        "hpke-p256-aes256gcm",
    )

    # Chart 1: encryption and decryption time.
    fig, ax = plt.subplots(figsize=(13, 7))

    for profile in profiles:
        for operation in ("encrypt", "decrypt"):
            selected = [
                row for row in results
                if row["profile"] == profile
                and row["operation"] == operation
            ]
            selected.sort(key=lambda row: row["payload_bytes"])

            if not selected:
                continue

            x = [row["payload_bytes"] / 1024 for row in selected]
            y = [row["median_ns"] / 1_000_000 for row in selected]

            ax.plot(
                x,
                y,
                marker="o",
                label=f"{profile} | {operation}",
            )

    ax.set_xscale("log", base=2)
    ax.set_xlabel("Payload size (KiB)")
    ax.set_ylabel("Median time (ms)")
    ax.set_title("Asymmetric encryption and decryption time")
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=7, loc="best")

    fig.tight_layout()
    fig.savefig(OUTPUT_DIR / "chart_operation_time.png", dpi=200)
    plt.close(fig)

    # Chart 2: ciphertext size compared with plaintext size.
    fig, ax = plt.subplots(figsize=(12, 7))

    for profile in profiles:
        selected = [
            row for row in results
            if row["profile"] == profile
            and row["operation"] == "encrypt"
        ]
        selected.sort(key=lambda row: row["payload_bytes"])

        if not selected:
            continue

        x = [row["payload_bytes"] / 1024 for row in selected]
        y = [row["ciphertext_bytes"] / 1024 for row in selected]

        ax.plot(
            x,
            y,
            marker="o",
            label=profile,
        )

    ax.set_xscale("log", base=2)
    ax.set_yscale("log", base=2)
    ax.set_xlabel("Plaintext size (KiB)")
    ax.set_ylabel("Ciphertext size (KiB)")
    ax.set_title("Ciphertext size by cryptographic profile")
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=8, loc="best")

    fig.tight_layout()
    fig.savefig(OUTPUT_DIR / "chart_ciphertext_size.png", dpi=200)
    plt.close(fig)

    print("Charts successfully created:")
    print(OUTPUT_DIR / "chart_operation_time.png")
    print(OUTPUT_DIR / "chart_ciphertext_size.png")


if __name__ == "__main__":
    main()