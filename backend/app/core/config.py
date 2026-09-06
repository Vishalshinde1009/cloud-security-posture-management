from typing import List, Union
from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"
    PROJECT_NAME: str = "Cloud Security Posture Management (CSPM)"
    API_V1_STR: str = "/api"
    VERSION: str = "1.0.0"

    # Operation Mode: 'mock' (safe offline demo/testing) or 'aws' (real read-only scan)
    CSPM_MODE: str = "mock"

    # Security & JWT
    SECRET_KEY: str = "default-insecure-key-override-via-env-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Initial Admin Seed
    INITIAL_ADMIN_EMAIL: str = "admin@cspm-security.local"
    INITIAL_ADMIN_PASSWORD: str = "AdminSecurePass123!"

    # Database connection URL
    DATABASE_URL: str = "sqlite:///./cspm.db"

    # CORS origins list
    CORS_ORIGINS: Union[str, List[str]] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
    ]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    # AWS Credentials (optional, read-only when CSPM_MODE=aws)
    AWS_DEFAULT_REGION: str = "us-east-1"
    AWS_ACCESS_KEY_ID: str = ""
    AWS_SECRET_ACCESS_KEY: str = ""
    AWS_SESSION_TOKEN: str = ""
    AWS_ASSUME_ROLE_ARN: str = ""

    # Risk threshold classifications
    RISK_THRESHOLD_CRITICAL: int = 90
    RISK_THRESHOLD_HIGH: int = 70
    RISK_THRESHOLD_MEDIUM: int = 40
    RISK_THRESHOLD_LOW: int = 0

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()
