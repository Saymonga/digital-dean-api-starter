"""Synthetic known-answer, random-salt and bounded-parsing tests."""
import re
import pytest

from app.security import passwords

PASSWORD = "Learning only 05!"


def test_fixed_profile_and_utf8_are_explicit():
    assert passwords.ITERATIONS == 600_000
    assert passwords.SALT_BYTES == 16
    assert passwords.DERIVED_BYTES == 32
    assert passwords.password_bytes("  Пароль для навчання  ") == "  Пароль для навчання  ".encode("utf-8")


def test_known_answer_for_fixed_synthetic_salt(monkeypatch):
    def fixed_salt(count):
        assert count == 16
        return bytes(range(16))
    monkeypatch.setattr(passwords.secrets, "token_bytes", fixed_salt)
    record, salt = passwords.make_password_record(PASSWORD)
    assert salt == "000102030405060708090a0b0c0d0e0f"
    # Independently verified with PyCryptodome, not a real user's credential.
    assert record == (
        "pbkdf2_sha256$600000$"
        "3dd76cec5c1fb2c8c61591bf14c8668636a3648feb24713eadf98a04e6879910")


def test_same_password_has_different_salts_and_records():
    first, salt1 = passwords.make_password_record(PASSWORD)
    second, salt2 = passwords.make_password_record(PASSWORD)
    assert re.fullmatch(r"[0-9a-f]{32}", salt1)
    assert re.fullmatch(r"[0-9a-f]{32}", salt2)
    assert salt1 != salt2 and first != second
    assert passwords.verify_password(PASSWORD, first, salt1) is True
    assert passwords.verify_password("Wrong password 05!", first, salt1) is False


def test_spaces_unicode_and_case_are_not_normalized():
    password = "  Пароль для навчання 5  "
    record, salt = passwords.make_password_record(password)
    assert passwords.verify_password(password, record, salt) is True
    assert passwords.verify_password(password.strip(), record, salt) is False
    assert passwords.verify_password(password.casefold(), record, salt) is False


@pytest.mark.parametrize("record,salt", [
    ("plain-text", "00" * 16),
    ("pbkdf2_sha256$1$" + "00" * 32, "00" * 16),
    ("pbkdf2_sha256$999999999999999999$" + "00" * 32, "00" * 16),
    ("sha256$600000$" + "00" * 32, "00" * 16),
    ("pbkdf2_sha256$600000$" + "ff" * 32, "not-hex"),
    ("pbkdf2_sha256$600000$" + "ff" * 31, "00" * 16),
    ("pbkdf2_sha256$600000$" + "ff" * 32, "00" * 15),
    ("pbkdf2_sha256$600000$" + "FF" * 32, "00" * 16),
    ("x" * 10000, "00" * 16),
], ids=["plain", "short-cost", "huge-cost", "wrong-algorithm", "bad-salt",
        "short-hash", "short-salt", "uppercase-hash", "oversized-record"])
def test_invalid_stored_values_rejected_before_kdf(monkeypatch, record, salt):
    def forbidden_kdf(*args, **kwargs):
        raise AssertionError("malformed profile reached the KDF")
    monkeypatch.setattr(passwords.hashlib, "pbkdf2_hmac", forbidden_kdf)
    assert passwords.verify_password(PASSWORD, record, salt) is False


@pytest.mark.parametrize("value", ["", "x" * 14, "x" * 129, "bad\x00password12345", "\ud800" * 15])
def test_registration_password_bounds(value):
    with pytest.raises(ValueError):
        passwords.password_bytes(value, registration=True)
