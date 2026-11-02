"""Параметри визначеного навчального профілю, не універсальні межі схем."""

KEY_BYTES = {
    "AES-128-GCM": 16,
    "AES-256-GCM": 32,
    "ChaCha20-Poly1305": 32,
}
BACKENDS = ("cryptography", "pycryptodome")
NONCE_BYTES = 12
TAG_BYTES = 16


def validate_profile(algorithm: str, key: bytes, nonce: bytes) -> None:
    """Перевірити алгоритм і довжини ключа та nonce."""

    if algorithm not in KEY_BYTES:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    if len(key) != KEY_BYTES[algorithm]:
        raise ValueError(
            f"Invalid key length for {algorithm}: "
            f"expected {KEY_BYTES[algorithm]} bytes"
        )

    if len(nonce) != NONCE_BYTES:
        raise ValueError(
            f"Invalid nonce length: expected {NONCE_BYTES} bytes"
        )