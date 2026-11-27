
"""Fixed educational PBKDF2 profile; do not reuse the fast hashes from lab 4."""
import hashlib
import hmac
import re
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
    """Return (password_record, salt_hex), never the cleartext password."""
    raw = password_bytes(password, registration=True)
    salt = secrets.token_bytes(SALT_BYTES)
    derived = hashlib.pbkdf2_hmac(
        "sha256", raw, salt, ITERATIONS, dklen=DERIVED_BYTES
    )
    record = f"{ALGORITHM}${ITERATIONS}${derived.hex()}"
    return record, salt.hex()


def verify_password(password: str, record: str, salt_hex: str) -> bool:
    """Verify only the fixed supported profile; reject malformed records safely."""
    try:
        raw = password_bytes(password)
    except (ValueError, TypeError):
        return False

    if not isinstance(record, str) or len(record) > 100:
        return False
    if not isinstance(salt_hex, str):
        return False
    if not re.fullmatch(r"[0-9a-f]{32}", salt_hex):
        return False

    parts = record.split("$")
    if len(parts) != 3:
        return False

    algorithm, iterations_text, digest_hex = parts
    if algorithm != ALGORITHM or iterations_text != str(ITERATIONS):
        return False
    if not re.fullmatch(r"[0-9a-f]{64}", digest_hex):
        return False

    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except ValueError:
        return False

    actual = hashlib.pbkdf2_hmac(
        "sha256", raw, salt, ITERATIONS, dklen=DERIVED_BYTES
    )
    return hmac.compare_digest(actual, expected)
