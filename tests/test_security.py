"""Tests for Security Core (Argon2, AES-256-GCM, Secret Masking, SSRF Guard)."""
import pytest

from app.core.security import (
    create_access_token,
    decode_access_token,
    decrypt_secret,
    encrypt_secret,
    get_password_hash,
    mask_secret,
    verify_password,
)
from app.core.ssrf import is_safe_ip, validate_outbound_url


def test_argon2_password_hashing():
    password = "SuperSecurePassword2026!"
    hashed = get_password_hash(password)

    assert hashed != password
    assert hashed.startswith("$argon2")
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


def test_jwt_token_lifecycle():
    token = create_access_token(
        subject="user-12345",
        extra_claims={"email": "analyst@poseidon.cti", "role": "CTI_ANALYST"}
    )
    assert isinstance(token, str)

    payload = decode_access_token(token)
    assert payload is not None
    assert payload["sub"] == "user-12345"
    assert payload["email"] == "analyst@poseidon.cti"
    assert payload["role"] == "CTI_ANALYST"
    assert payload["iss"] == "poseidon-cti"


def test_jwt_invalid_token():
    assert decode_access_token("malformed.token.here") is None


def test_aes_256_gcm_secret_encryption():
    raw_api_key = "threatfox-api-secret-key-998877665544"
    encrypted = encrypt_secret(raw_api_key)

    # Assert ciphertext differs from plaintext
    assert encrypted != raw_api_key

    # Decrypt and compare
    decrypted = decrypt_secret(encrypted)
    assert decrypted == raw_api_key


def test_secret_masking():
    assert mask_secret("9F3A") == "••••••••"
    assert mask_secret("MY_SUPER_SECRET_API_KEY_9F3A") == "••••••••••••9F3A"
    assert mask_secret("") == ""


def test_ssrf_ip_blocklist():
    # Restricted IPs
    assert is_safe_ip("127.0.0.1") is False
    assert is_safe_ip("10.0.0.1") is False
    assert is_safe_ip("172.16.0.1") is False
    assert is_safe_ip("192.168.1.1") is False
    assert is_safe_ip("169.254.169.254") is False  # Cloud metadata
    assert is_safe_ip("::1") is False

    # Public Safe IPs
    assert is_safe_ip("8.8.8.8") is True
    assert is_safe_ip("1.1.1.1") is True
    assert is_safe_ip("185.220.101.5") is True


def test_ssrf_url_validation():
    # Valid safe public URL
    safe_url = "https://threatfox-api.abuse.ch/api/v1/"
    assert validate_outbound_url(safe_url) == safe_url

    # Malicious URLs targeting metadata or internal infrastructure
    with pytest.raises(ValueError):
        validate_outbound_url("http://169.254.169.254/latest/meta-data/")

    with pytest.raises(ValueError):
        validate_outbound_url("http://127.0.0.1:8000/admin")

    with pytest.raises(ValueError):
        validate_outbound_url("gopher://127.0.0.1:6379/")
