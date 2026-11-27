
"""Hashing adapters for whole and chunked processing."""

from app.security.hashing import profiles


def _validate_inputs(algorithm: str, data: bytes, mode: str) -> None:
    if not isinstance(algorithm, str) or algorithm not in profiles.PROFILES:
        raise ValueError("unknown hash profile")

    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")

    if mode not in ("whole", "chunked"):
        raise ValueError("mode must be 'whole' or 'chunked'")


def prepare_operation(algorithm: str, data: bytes, mode: str = "whole"):
    """Prepare immutable input chunks and return a repeatable operation."""
    _validate_inputs(algorithm, data, mode)

    if mode == "whole":
        chunks = (data,)
    else:
        chunks = tuple(
            data[index:index + profiles.CHUNK_BYTES]
            for index in range(0, len(data), profiles.CHUNK_BYTES)
        )

    if not chunks:
        chunks = (b"",)

    def operation() -> bytes:
        hasher = profiles.make_hasher(algorithm)
        for chunk in chunks:
            hasher.update(chunk)
        return hasher.digest()

    return operation


def hash_bytes(algorithm: str, data: bytes, mode: str = "whole") -> bytes:
    """Hash bytes using a fresh hash object for every call."""
    return prepare_operation(algorithm, data, mode)()


def hamming_bits(left: bytes, right: bytes) -> int:
    """Return the number of differing bits in two byte strings."""
    if not isinstance(left, bytes) or not isinstance(right, bytes):
        raise TypeError("inputs must be bytes")

    if not left or not right:
        raise ValueError("inputs must not be empty")

    if len(left) != len(right):
        raise ValueError("inputs must have equal lengths")

    return sum((a ^ b).bit_count() for a, b in zip(left, right))
