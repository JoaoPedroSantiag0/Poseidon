"""Poseidon Application Configuration."""
import base64
import os

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    PROJECT_NAME: str = "POSEIDON CTI"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"

    # Database
    # Default to local async sqlite for zero-friction setup, supports postgresql+asyncpg://...
    DATABASE_URL: str = "sqlite+aiosqlite:///./poseidon.db"

    # JWT & Auth
    SECRET_KEY: str = os.getenv("POSEIDON_SECRET_KEY", "poseidon-super-secret-key-change-in-production-2026")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 12  # 12 hours

    # AES-256-GCM Key for API key encryption at rest (32 bytes urlsafe base64)
    # If not provided, generates deterministic fallback for dev, logs warning in prod
    ENCRYPTION_KEY: str = os.getenv(
        "POSEIDON_ENCRYPTION_KEY",
        base64.urlsafe_b64encode(b"POSEIDON_MASTER_KEY_32BYTES_26!").decode()
    )

    # CORS
    BACKEND_CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ]

    # Initial Seed Credentials
    DEFAULT_ADMIN_EMAIL: str = "admin@poseidon.cti"
    DEFAULT_ADMIN_PASSWORD: str = "PoseidonAdmin2026!#"
    DEFAULT_ADMIN_NAME: str = "Poseidon System Administrator"
    DEFAULT_ORG_NAME: str = "Poseidon Threat Operations"
    # AI Analyst Provider Settings
    GEMINI_API_KEY: str | None = os.getenv("GEMINI_API_KEY")
    OPENAI_API_KEY: str | None = os.getenv("OPENAI_API_KEY")
    ANTHROPIC_API_KEY: str | None = os.getenv("ANTHROPIC_API_KEY")
    OLLAMA_BASE_URL: str | None = os.getenv("OLLAMA_BASE_URL")
    AI_MODEL_NAME: str = os.getenv("POSEIDON_AI_MODEL", "gemini-1.5-pro")

    # TAXII 2.1 Server Settings
    TAXII_SERVER_TITLE: str = os.getenv("TAXII_SERVER_TITLE", "POSEIDON TAXII 2.1 Server")
    TAXII_SERVER_DESCRIPTION: str = os.getenv(
        "TAXII_SERVER_DESCRIPTION", "Enterprise Cyber Threat Intelligence Exchange Node"
    )
    TAXII_SERVER_CONTACT: str = os.getenv("TAXII_SERVER_CONTACT", "soc-cti@poseidon.sec")
    TAXII_DEFAULT_API_ROOT: str = os.getenv("TAXII_DEFAULT_API_ROOT", "root")
    TAXII_MAX_CONTENT_LENGTH: int = int(os.getenv("TAXII_MAX_CONTENT_LENGTH", "10485760"))

    # Live MISP Integration Settings
    MISP_DEFAULT_URL: str = os.getenv("MISP_DEFAULT_URL", "")
    MISP_DEFAULT_API_KEY: str = os.getenv("MISP_DEFAULT_API_KEY", "")
    MISP_VERIFY_SSL: bool = os.getenv("MISP_VERIFY_SSL", "true").lower() in ("true", "1")


settings = Settings()
