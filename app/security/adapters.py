"""Спільний контракт для cryptography та PyCryptodome без відкритого fallback."""

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from Crypto.Cipher import AES, ChaCha20_Poly1305

from app.security.profiles import (
    BACKENDS,
    TAG_BYTES,
    validate_profile,
)


class CiphertextError(Exception):
    """Повідомлення не пройшло перевірку автентичності."""


def seal_bytes(backend, algorithm, key, nonce, data, aad):
    """Повернути ciphertext і tag після перевірки профілю та бібліотеки."""

    validate_profile(algorithm, key, nonce)

    if backend not in BACKENDS:
        raise ValueError(f"Unsupported backend: {backend}")

    if backend == "cryptography":
        if algorithm in ("AES-128-GCM", "AES-256-GCM"):
            encrypted = AESGCM(key).encrypt(nonce, data, aad)
        elif algorithm == "ChaCha20-Poly1305":
            encrypted = ChaCha20Poly1305(key).encrypt(nonce, data, aad)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        return encrypted[:-TAG_BYTES], encrypted[-TAG_BYTES:]

    if algorithm in ("AES-128-GCM", "AES-256-GCM"):
        cipher = AES.new(
            key,
            AES.MODE_GCM,
            nonce=nonce,
            mac_len=TAG_BYTES,
        )
    elif algorithm == "ChaCha20-Poly1305":
        cipher = ChaCha20_Poly1305.new(
            key=key,
            nonce=nonce,
        )
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    return ciphertext, tag


def open_bytes(backend, algorithm, key, nonce, ct, tag, aad):
    """Повернути відкриті байти тільки після перевірки повного тега."""

    validate_profile(algorithm, key, nonce)

    if backend not in BACKENDS:
        raise ValueError(f"Unsupported backend: {backend}")

    if len(tag) != TAG_BYTES:
        raise CiphertextError("Invalid authentication tag length")

    try:
        if backend == "cryptography":
            if algorithm in ("AES-128-GCM", "AES-256-GCM"):
                return AESGCM(key).decrypt(nonce, ct + tag, aad)

            if algorithm == "ChaCha20-Poly1305":
                return ChaCha20Poly1305(key).decrypt(
                    nonce,
                    ct + tag,
                    aad,
                )

            raise ValueError(f"Unsupported algorithm: {algorithm}")

        if algorithm in ("AES-128-GCM", "AES-256-GCM"):
            cipher = AES.new(
                key,
                AES.MODE_GCM,
                nonce=nonce,
                mac_len=TAG_BYTES,
            )
        elif algorithm == "ChaCha20-Poly1305":
            cipher = ChaCha20_Poly1305.new(
                key=key,
                nonce=nonce,
            )
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        cipher.update(aad)
        return cipher.decrypt_and_verify(ct, tag)

    except (InvalidTag, ValueError) as exc:
        raise CiphertextError("Ciphertext authentication failed") from exc