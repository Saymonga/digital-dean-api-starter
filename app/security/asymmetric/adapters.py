
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    padding,
    rsa,
    x25519,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hpke import (
    AEAD,
    KDF,
    KEM,
    Suite,
)

from app.security.asymmetric.profiles import (
    CONTEXT,
    PROFILES,
    KEY_PROFILES,
)


class DecryptionError(ValueError):
    """Единая безопасная ошибка отклонения криптографического сообщения."""


def generate_keypair(key_profile: str) -> tuple[object, object]:
    """Создаёт новую пару ключей для разрешённого профиля."""

    if key_profile not in KEY_PROFILES:
        raise ValueError("unsupported key profile")

    if key_profile == "rsa-2048":
        private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        return private, private.public_key()

    if key_profile == "rsa-3072":
        private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072,
        )
        return private, private.public_key()

    if key_profile == "x25519":
        private = x25519.X25519PrivateKey.generate()
        return private, private.public_key()

    if key_profile == "p256":
        private = ec.generate_private_key(ec.SECP256R1())
        return private, private.public_key()

    raise ValueError("unsupported key profile")


def _oaep(context: bytes) -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=context,
    )


def _hpke_suite(profile: str) -> Suite:
    if profile == "hpke-x25519-aes256gcm":
        kem = KEM.X25519
    elif profile == "hpke-p256-aes256gcm":
        kem = KEM.P256
    else:
        raise ValueError("unsupported HPKE profile")

    return Suite(
        kem,
        KDF.HKDF_SHA256,
        AEAD.AES_256_GCM,
    )


def encrypt(
    profile: str,
    public: object,
    message: bytes,
    *,
    context: bytes = CONTEXT,
) -> bytes:
    """Шифрует сообщение согласно выбранному профилю."""

    if profile not in PROFILES:
        raise ValueError("unsupported encryption profile")

    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")

    if not isinstance(context, bytes):
        raise TypeError("context must be bytes")

    spec = PROFILES[profile]

    if spec.group == "direct":
        if not isinstance(public, rsa.RSAPublicKey):
            raise ValueError("RSA public key required")

        expected_bits = 2048 if spec.key_profile == "rsa-2048" else 3072
        if public.key_size != expected_bits:
            raise ValueError("wrong RSA key size")

        if len(message) > spec.key_profile.count("0") * 0 + (
            expected_bits // 8 - 2 * 32 - 2
        ):
            raise ValueError("message too large for RSA-OAEP")

        return public.encrypt(message, _oaep(context))

    if profile == "rsa3072-oaep-aes256gcm":
        if not isinstance(public, rsa.RSAPublicKey):
            raise ValueError("RSA public key required")

        if public.key_size != 3072:
            raise ValueError("RSA-3072 required")

        aes_key = AESGCM.generate_key(bit_length=256)
        nonce = secrets.token_bytes(12)

        wrapped_key = public.encrypt(aes_key, _oaep(context))
        encrypted = AESGCM(aes_key).encrypt(
            nonce,
            message,
            context,
        )

        return wrapped_key + nonce + encrypted

    if profile in (
        "hpke-x25519-aes256gcm",
        "hpke-p256-aes256gcm",
    ):
        suite = _hpke_suite(profile)
        return suite.encrypt(
            message,
            public,
            info=context,
        )

    raise ValueError("unsupported encryption profile")


def _decrypt(
    profile: str,
    private: object,
    envelope: bytes,
    context: bytes,
) -> bytes:
    """Проверяет формат конверта и выполняет расшифрование."""

    if not isinstance(envelope, bytes):
        raise ValueError("invalid envelope")

    spec = PROFILES[profile]

    if spec.group == "direct":
        if not isinstance(private, rsa.RSAPrivateKey):
            raise ValueError("RSA private key required")

        expected_bits = 2048 if spec.key_profile == "rsa-2048" else 3072
        if private.key_size != expected_bits:
            raise ValueError("wrong RSA key size")

        expected_length = expected_bits // 8
        if len(envelope) != expected_length:
            raise ValueError("invalid RSA envelope length")

        return private.decrypt(envelope, _oaep(context))

    if profile == "rsa3072-oaep-aes256gcm":
        if not isinstance(private, rsa.RSAPrivateKey):
            raise ValueError("RSA private key required")

        if private.key_size != 3072:
            raise ValueError("RSA-3072 required")

        wrapped_length = 384
        nonce_length = 12
        tag_length = 16

        if len(envelope) < wrapped_length + nonce_length + tag_length:
            raise ValueError("invalid hybrid envelope length")

        wrapped_key = envelope[:wrapped_length]
        nonce = envelope[wrapped_length:wrapped_length + nonce_length]
        ciphertext = envelope[wrapped_length + nonce_length:]

        aes_key = private.decrypt(wrapped_key, _oaep(context))

        if len(aes_key) != 32:
            raise ValueError("invalid AES key")

        return AESGCM(aes_key).decrypt(
            nonce,
            ciphertext,
            context,
        )

    if profile in (
        "hpke-x25519-aes256gcm",
        "hpke-p256-aes256gcm",
    ):
        suite = _hpke_suite(profile)
        return suite.decrypt(
            envelope,
            private,
            info=context,
        )

    raise ValueError("unsupported encryption profile")


def decrypt(
    profile: str,
    private: object,
    envelope: bytes,
    *,
    context: bytes = CONTEXT,
) -> bytes:
    """Возвращает открытый текст только после успешной проверки."""

    if profile not in PROFILES:
        raise ValueError("unsupported encryption profile")

    try:
        return _decrypt(profile, private, envelope, context)
    except (InvalidTag, ValueError, TypeError) as exc:
        raise DecryptionError("decryption rejected") from exc
