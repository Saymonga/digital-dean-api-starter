"""Маршрути захищених нотаток студентів."""

from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Request, status

from app.repositories.student_repository import (
    student_repository,
    StudentNotFoundError,
)
from app.repositories.secure_note_repository import (
    repository as note_repository,
    EncryptedNote,
)
from app.schemas.secure_note import (
    NoteCreate,
    NoteMetadata,
    NoteRead,
)
from app.security.adapters import (
    seal_bytes,
    open_bytes,
    CiphertextError,
)
from app.security.context import note_aad
from app.security.profiles import NONCE_BYTES, TAG_BYTES


router = APIRouter(
    prefix="/api/v1/students",
    tags=["secure-notes"],
)


@router.post(
    "/{student_id}/secure-notes",
    response_model=NoteMetadata,
    status_code=status.HTTP_201_CREATED,
)
def create_secure_note(
    student_id: UUID,
    payload: NoteCreate,
    request: Request,
):
    """Створити та зберегти зашифровану нотатку."""

    try:
        student_repository.get(student_id)
    except StudentNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Student not found",
        )

    process_key = request.app.state.process_key

    note_id = uuid4()
    algorithm = "AES-256-GCM"
    backend = "cryptography"
    category = payload.category

    try:
        nonce = process_key.nonces.next()

        aad = note_aad(
            str(student_id),
            str(note_id),
            algorithm,
            str(process_key.key_id),
            category,
        )

        ciphertext, tag = seal_bytes(
            backend,
            algorithm,
            process_key.key,
            nonce,
            payload.text.encode("utf-8"),
            aad,
        )

        encrypted_note = EncryptedNote(
            version=1,
            student_id=student_id,
            note_id=note_id,
            algorithm=algorithm,
            backend=backend,
            key_id=process_key.key_id,
            category=category,
            nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
        )

        note_repository.add(encrypted_note)

    except RuntimeError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Protected note unavailable",
        )

    return NoteMetadata(
        id=note_id,
        student_id=student_id,
        algorithm=algorithm,
        category=category,
    )


@router.get(
    "/{student_id}/secure-notes/{note_id}",
    response_model=NoteRead,
)
def read_secure_note(
    student_id: UUID,
    note_id: UUID,
    request: Request,
):
    """Прочитати нотатку лише після перевірки автентичності."""

    try:
        student_repository.get(student_id)
    except StudentNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Student not found",
        )

    try:
        encrypted_note = note_repository.get(
            student_id,
            note_id,
        )
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Protected note not found",
        )

    process_key = request.app.state.process_key

    try:
        if encrypted_note.version != 1:
            raise CiphertextError("Unsupported envelope version")

        if encrypted_note.key_id != process_key.key_id:
            raise CiphertextError("Unknown encryption key")

        if len(encrypted_note.nonce) != NONCE_BYTES:
            raise CiphertextError("Invalid nonce length")

        if len(encrypted_note.tag) != TAG_BYTES:
            raise CiphertextError("Invalid tag length")

        category = encrypted_note.category

        if category not in (
            "general",
            "academic",
            "administrative",
        ):
            raise CiphertextError("Invalid note category")

        aad = note_aad(
            str(student_id),
            str(note_id),
            encrypted_note.algorithm,
            str(encrypted_note.key_id),
            category,
        )

        plaintext = open_bytes(
            encrypted_note.backend,
            encrypted_note.algorithm,
            process_key.key,
            encrypted_note.nonce,
            encrypted_note.ciphertext,
            encrypted_note.tag,
            aad,
        )

        text = plaintext.decode("utf-8")

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Protected note unavailable",
        )

    return NoteRead(
        id=note_id,
        student_id=student_id,
        algorithm=encrypted_note.algorithm,
        category=category,
        text=text,
    )