"""Матеріал ключа створюють один раз під час запуску процесу API."""

from dataclasses import dataclass, field
from secrets import token_bytes
from uuid import UUID, uuid4

from app.security.nonce import NonceSequence


@dataclass(frozen=True)
class ProcessKey:
    key_id: UUID
    key: bytes = field(repr=False)
    nonces: NonceSequence = field(repr=False)


def create_process_key(limit: int = 1_000_000) -> ProcessKey:
    """Створити один набір ключа та лічильника nonce для процесу API."""

    return ProcessKey(
        key_id=uuid4(),
        key=token_bytes(32),
        nonces=NonceSequence(limit),
    )