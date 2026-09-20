"""Poseidon Security Engine: Argon2 Hashing, JWT Tokens, and AES-256-GCM Secret Encryption."""
import base64
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import argon2
import jwt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings

# Initialize Argon2 password hasher with robust parameters
_hasher = argon2.PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MB
    parallelism=2,
    hash_len=32,
    salt_len=16
)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against an Argon2 hash."""
    try:
        return _hasher.verify(hashed_password, plain_password)
    except Exception:
        return False


def get_password_hash(password: str) -> str:
    """Computes an Argon2id hash for a plain password."""
    return _hasher.hash(password)


def create_access_token(
    subject: str | Any,
    expires_delta: timedelta | None = None,
    extra_claims: dict[str, Any] | None = None
) -> str:
    """Generates a signed JWT access token."""
    now = datetime.now(UTC)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode: dict[str, Any] = {
        "sub": str(subject),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "iss": "poseidon-cti"
    }
    if extra_claims:
        to_encode.update(extra_claims)

    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> dict[str, Any] | None:
    """Decodes and validates a signed JWT access token."""
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            issuer="poseidon-cti"
        )
        return payload
    except Exception:
        return None


# AES-256-GCM Secret Encryption & Decryption
def _get_aes_key() -> bytes:
    """Derives a strict 32-byte key for AES-256-GCM."""
    raw_key = base64.urlsafe_b64decode(settings.ENCRYPTION_KEY.encode())
    if len(raw_key) != 32:
        import hashlib
        return hashlib.sha256(raw_key).digest()
    return raw_key


def encrypt_secret(plaintext: str) -> str:
    """Encrypts sensitive plaintext (such as API keys) using AES-256-GCM.

    Returns standard Base64 string containing: 12-byte nonce + ciphertext + 16-byte tag.
    """
    if not plaintext:
        return ""
    key = _get_aes_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    payload = nonce + ciphertext
    return base64.b64encode(payload).decode("utf-8")


def decrypt_secret(encrypted_b64: str) -> str:
    """Decrypts an AES-256-GCM encrypted Base64 string."""
    if not encrypted_b64:
        return ""
    try:
        key = _get_aes_key()
        aesgcm = AESGCM(key)
        payload = base64.b64decode(encrypted_b64.encode("utf-8"))
        if len(payload) < 28:  # 12 nonce + 16 tag minimum
            raise ValueError("Ciphertext payload too short")
        nonce = payload[:12]
        ciphertext = payload[12:]
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_bytes.decode("utf-8")
    except Exception as exc:
        raise ValueError(f"Decryption failed: {exc!s}") from exc


def mask_secret(secret_value: str) -> str:
    """Returns a masked version of a secret for UI presentation (e.g. ************9F3A)."""
    if not secret_value:
        return ""
    cleaned = secret_value.strip()
    if len(cleaned) <= 4:
        return "•" * 8
    visible = cleaned[-4:]
    return f"{'•' * 12}{visible}"
