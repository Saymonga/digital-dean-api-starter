"""Fixed educational PBKDF2 profile; do not reuse the fast hashes from lab 4."""
import hashlib
import hmac
import secrets

ALGORITHM = "pbkdf2_sha256"
ITERATIONS = 600_000
SALT_BYTES = 16
DERIVED_BYTES = 32
MIN_PASSWORD_CHARS = 15
MAX_PASSWORD_CHARS = 128
MAX_PASSWORD_BYTES = 512


def password_bytes(password: str, *, registration: bool = False) -> bytes:
    """Preserve whitespace/case; encode strict UTF-8, bounded before the KDF."""
    if not isinstance(password, str):
        raise ValueError("password must be text")
    minimum = MIN_PASSWORD_CHARS if registration else 1
    if not minimum <= len(password) <= MAX_PASSWORD_CHARS or "\x00" in password:
        raise ValueError("password length or characters invalid")
    try:
        raw = password.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError("password encoding invalid") from exc
    if len(raw) > MAX_PASSWORD_BYTES:
        raise ValueError("password byte length invalid")
    return raw


def make_password_record(password: str) -> tuple[str, str]:
    """Return (password_record, salt_hex), never the cleartext password.

    TODO: use a fresh secrets.token_bytes(SALT_BYTES), PBKDF2-HMAC-SHA256,
    and lowercase hex. Record format is pbkdf2_sha256$600000$<64 hex chars>.
    The salt is stored separately as exactly 32 lowercase hex characters.
    """
    raise NotImplementedError("TODO: create a salted password record")


def verify_password(password: str, record: str, salt_hex: str) -> bool:
    """TODO: bounded strict parsing, fixed supported profile, compare_digest.

    Return False for wrong passwords and malformed/unsupported stored values.
    Do not run the KDF with an arbitrary iteration count from the database.
    Do not trim or case-convert the password. Never log these arguments.
    """
    raise NotImplementedError("TODO: verify a password without secret output")
