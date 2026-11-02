"""Асоційовані дані пов’язують повідомлення з очікуваним ресурсом."""

import json


def note_aad(
    student_id,
    note_id,
    algorithm,
    key_id,
    category="general",
) -> bytes:
    """Створити канонічний контекст для автентифікації нотатки."""

    values = (student_id, note_id, algorithm, key_id, category)

    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError("AAD identifiers must be non-empty strings")

    if category not in ("general", "academic", "administrative"):
        raise ValueError("Unsupported note category")

    context = {
        "version": 1,
        "student_id": student_id,
        "note_id": note_id,
        "algorithm": algorithm,
        "key_id": key_id,
        "category": category,
    }

    return json.dumps(
        context,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")