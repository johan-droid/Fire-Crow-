import json
import os
from pathlib import Path
from typing import Annotated, Any, Literal
from pydantic_settings import BaseSettings, SettingsConfigDict, NoDecode
from pydantic import Field, field_validator, model_validator


BACKEND_DIR = Path(__file__).resolve().parents[1]
WORKSPACE_DIR = Path(__file__).resolve().parents[1]

# Load env files into the OS environment BEFORE instantiating Settings.
# This sidesteps a pydantic-settings bug (v2.14.x) where its env_file
# tuple may not load the second file (.env.local) correctly, causing
# placeholders from .env to shadow real keys from .env.local.
#
# Order matters: .env.local is loaded FIRST so its real keys take hold.
# Then .env is loaded SECOND (no override), so its empty placeholders
# cannot overwrite the real keys from .env.local.  Pre-existing OS
# environment variables (e.g. set by test conftest) are never touched
# because load_dotenv defaults to override=False.
_env_local = WORKSPACE_DIR / ".env.local"
_env_file = WORKSPACE_DIR / ".env"
try:
    from dotenv import load_dotenv
    load_dotenv(_env_local)
    load_dotenv(_env_file)
except ImportError:
    pass


class Settings(BaseSettings):
    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def normalize_sqlite_database_url(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        if not value.startswith("sqlite:///"):
            return value

        raw_path = value.removeprefix("sqlite:///")
        if raw_path in {"", ":memory:"}:
            return value

        database_path = Path(raw_path)
        if not database_path.is_absolute():
            database_path = (WORKSPACE_DIR / database_path).resolve()

        return f"sqlite:///{database_path.as_posix()}"

    @model_validator(mode="after")
    def _ensure_critical_secrets(self) -> "Settings":
        """Validate that all production‑critical secrets are set.
        This runs after the model is populated from env files. In production
        (`DEBUG=False`) any empty value for a secret will raise a RuntimeError
        and abort startup, preventing the service from running with insecure defaults.
        """
        insecure_dev_values = {
            "",
            "dev_secret_key_change_in_production_1234567890",
            "change_me",
            "changeme",
            "secret",
            "development",
            "dev_only_firecrow_local_secret_key_32_bytes_minimum_DO_NOT_USE_IN_PRODUCTION",
            "local_dev_secret_key_change_me_1234567890",
            "local_dev_encryption_key_change_me_1234567890",
        }

        if self.DEBUG:
            if not self.SECRET_KEY:
                object.__setattr__(self, "SECRET_KEY", "local_dev_secret_key_change_me_1234567890")
            if not self.ENCRYPTION_KEY:
                object.__setattr__(self, "ENCRYPTION_KEY", "local_dev_encryption_key_change_me_1234567890")
        else:
            if not self.SECRET_KEY:
                raise ValueError("SECRET_KEY is required. Set a strong random value (min 32 chars).")

            if self.SECRET_KEY.strip() in insecure_dev_values:
                raise ValueError("SECRET_KEY cannot use a known development value. Generate a secure random key.")

            if len(self.SECRET_KEY) < 32:
                raise ValueError("SECRET_KEY must be at least 32 characters.")

            if not self.ENCRYPTION_KEY:
                object.__setattr__(self, "ENCRYPTION_KEY", self.SECRET_KEY)
            else:
                if self.ENCRYPTION_KEY.strip() in insecure_dev_values:
                    raise ValueError("ENCRYPTION_KEY cannot use a known development value. Generate a secure random key.")

                if len(self.ENCRYPTION_KEY) < 32:
                    raise ValueError("ENCRYPTION_KEY must be at least 32 characters.")

        if not self.DEBUG:
            missing = []
            required_names = ["SECRET_KEY"]
            if self.DATABASE_BACKEND == "postgresql":
                required_names.append("DATABASE_URL")
            for name in required_names:
                if not getattr(self, name):
                    missing.append(name)
            if missing:
                raise RuntimeError(
                    f"Missing critical secrets for production: {', '.join(missing)}"
                )
            if self.DATABASE_BACKEND == "postgresql" and self.DATABASE_URL.startswith("sqlite"):
                raise ValueError("SQLite DATABASE_URL is only allowed when DEBUG=True.")
            if self.FIRE_CROW_SCANNER_IMAGE.endswith(":latest"):
                raise ValueError("FIRE_CROW_SCANNER_IMAGE must be pinned in production and cannot use :latest.")
            if not getattr(self, "REPORT_LOCAL_FALLBACK", True):
                if not self.R2_ACCESS_KEY_ID or not self.R2_SECRET_ACCESS_KEY or not self.R2_BUCKET_NAME or not self.R2_ENDPOINT_URL:
                    raise ValueError("Cloud storage configuration is missing, but REPORT_LOCAL_FALLBACK is False.")

        if self.DATABASE_BACKEND == "neo4j":
            if not self.NEO4J_URI:
                raise ValueError("NEO4J_URI is required when DATABASE_BACKEND=neo4j.")
            if not self.NEO4J_USER:
                raise ValueError("NEO4J_USER is required when DATABASE_BACKEND=neo4j.")
            if not self.NEO4J_PASSWORD:
                raise ValueError("NEO4J_PASSWORD is required when DATABASE_BACKEND=neo4j.")
            if len(self.NEO4J_PASSWORD) < 16:
                raise ValueError("NEO4J_PASSWORD must be at least 16 characters.")
            if self.NEO4J_PASSWORD.strip().lower() in {"password", "neo4j", "changeme", "change_me", "admin"}:
                raise ValueError("NEO4J_PASSWORD cannot use a default or known weak value.")
            if self.NEO4J_ENFORCE_TLS and not self.NEO4J_URI.startswith(("neo4j+s://", "bolt+s://")):
                local_prefixes = ("neo4j://localhost", "bolt://localhost", "neo4j://127.0.0.1", "bolt://127.0.0.1")
                if not any(self.NEO4J_URI.startswith(prefix) for prefix in local_prefixes):
                    raise ValueError("NEO4J_URI must use TLS for non-local deployments when NEO4J_ENFORCE_TLS=true.")

        if self.DATABASE_BACKEND == "postgresql" and not self.POSTGRES_MIGRATION_SOURCE_URL:
            object.__setattr__(self, "POSTGRES_MIGRATION_SOURCE_URL", self.DATABASE_URL)

        # Inject REDIS_PASSWORD into REDIS_URL if provided
        if self.REDIS_PASSWORD:
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(self.REDIS_URL)
            if parsed.scheme in ("redis", "rediss") and not parsed.password:
                netloc = parsed.netloc
                if "@" in netloc:
                    user_host = netloc.split("@", 1)
                    user = user_host[0]
                    host = user_host[1]
                    if ":" not in user:
                        netloc = f"{user}:{self.REDIS_PASSWORD}@{host}"
                else:
                    netloc = f":{self.REDIS_PASSWORD}@{netloc}"
                new_url = urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
                object.__setattr__(self, "REDIS_URL", new_url)
        return self
    # --- Server Settings ---
    PORT: int = Field(default=8000, validation_alias="PORT")
    HOST: str = Field(default="0.0.0.0", validation_alias="HOST")
    DEBUG: bool = Field(default=False, validation_alias="DEBUG")
    SECRET_KEY: str = Field(default="", validation_alias="SECRET_KEY")
    ENCRYPTION_KEY: str = Field(default="", validation_alias="ENCRYPTION_KEY")
    FRONTEND_URL: str = Field(default="", validation_alias="FRONTEND_URL")
    CORS_ORIGINS: str = Field(default="", validation_alias="CORS_ORIGINS")

    # --- Security and Compliance Constants ---
    PRIVACY_POLICY_VERSION: str = Field(default="2026-06-06", validation_alias="PRIVACY_POLICY_VERSION")
    TERMS_VERSION: str = Field(default="2026-06-06", validation_alias="TERMS_VERSION")
    GITHUB_OAUTH_SCOPES: Annotated[list[str], NoDecode] = Field(
        default=["repo", "workflow", "read:org", "user:email"],
        validation_alias="GITHUB_OAUTH_SCOPES"
    )
    # Scope descriptions for frontend display:
    # - repo: Full control of private repositories (issues, labels, PRs, code)
    # - workflow: Update GitHub Action workflows
    # - read:org: Read organization membership
    # - user:email: Access user email addresses
    LOGIN_FAILURE_WINDOW_MINUTES: int = Field(default=10, validation_alias="LOGIN_FAILURE_WINDOW_MINUTES")
    LOGIN_FAILURE_LIMIT: int = Field(default=5, validation_alias="LOGIN_FAILURE_LIMIT")
    MIN_PASSWORD_LENGTH: int = Field(default=12, validation_alias="MIN_PASSWORD_LENGTH")
    MAX_REQUEST_BODY_BYTES: int = Field(default=10 * 1024 * 1024, validation_alias="MAX_REQUEST_BODY_BYTES")  # 10MB
    MAX_JSON_BODY_BYTES: int = Field(default=2 * 1024 * 1024, validation_alias="MAX_JSON_BODY_BYTES")  # 2MB
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=1440, validation_alias="JWT_ACCESS_TOKEN_EXPIRE_MINUTES")
    AUTH_COOKIE_NAME: str = Field(default="fc_access_token", validation_alias="AUTH_COOKIE_NAME")
    AUTH_COOKIE_SECURE: bool = Field(default=True, validation_alias="AUTH_COOKIE_SECURE")
    AUTH_COOKIE_HTTPONLY: bool = Field(default=True, validation_alias="AUTH_COOKIE_HTTPONLY")
    AUTH_COOKIE_SAMESITE: Literal['lax', 'strict', 'none'] | None = Field(default="strict", validation_alias="AUTH_COOKIE_SAMESITE")
    CSRF_ENABLED: bool = Field(default=True, validation_alias="CSRF_ENABLED")

    # --- MFA Settings ---
    MFA_ENFORCE_FOR_ADMINS: bool = Field(default=True, validation_alias="MFA_ENFORCE_FOR_ADMINS")
    MFA_TOTP_ISSUER: str = Field(default="Fire Crow", validation_alias="MFA_TOTP_ISSUER")
    MFA_MAX_FAILED_ATTEMPTS: int = Field(default=5, validation_alias="MFA_MAX_FAILED_ATTEMPTS")
    MFA_RECOVERY_CODE_COUNT: int = Field(default=8, validation_alias="MFA_RECOVERY_CODE_COUNT")

    # --- SSO Settings ---
    SSO_OIDC_SCOPES: str = Field(default="openid email profile", validation_alias="SSO_OIDC_SCOPES")
    SSO_ALLOW_AUTO_PROVISION: bool = Field(default=False, validation_alias="SSO_ALLOW_AUTO_PROVISION")
    SSO_DEFAULT_ROLE_ID: str = Field(default="", validation_alias="SSO_DEFAULT_ROLE_ID")

    # --- PAM Settings ---
    PAM_MAX_DURATION_MINUTES: int = Field(default=480, validation_alias="PAM_MAX_DURATION_MINUTES")
    PAM_MIN_DURATION_MINUTES: int = Field(default=1, validation_alias="PAM_MIN_DURATION_MINUTES")
    PAM_MAX_PENDING_REQUESTS: int = Field(default=3, validation_alias="PAM_MAX_PENDING_REQUESTS")
    PAM_CLEANUP_INTERVAL_MINUTES: int = Field(default=15, validation_alias="PAM_CLEANUP_INTERVAL_MINUTES")

    # --- IAM Settings ---
    IAM_DORMANT_DAYS_THRESHOLD: int = Field(default=90, validation_alias="IAM_DORMANT_DAYS_THRESHOLD")
    IAM_SHARED_ACCOUNT_IP_THRESHOLD: int = Field(default=5, validation_alias="IAM_SHARED_ACCOUNT_IP_THRESHOLD")
    IAM_SERVICE_TOKEN_PREFIX: str = Field(default="fc_svc_", validation_alias="IAM_SERVICE_TOKEN_PREFIX")

    # --- Database & Cache ---
    DATABASE_BACKEND: Literal["postgresql", "neo4j"] = Field(default="postgresql", validation_alias="DATABASE_BACKEND")
    DATABASE_URL: str = Field(
        default="",
        validation_alias="DATABASE_URL"
    )
    DATABASE_POOL_SIZE: int = Field(default=50)
    DATABASE_MAX_OVERFLOW: int = Field(default=50)
    DATABASE_POOL_TIMEOUT: int = Field(default=30)
    DATABASE_POOL_RECYCLE: int = Field(default=1800)
    POSTGRES_MIGRATION_SOURCE_URL: str = Field(default="", validation_alias="POSTGRES_MIGRATION_SOURCE_URL")
    NEO4J_URI: str = Field(default="", validation_alias="NEO4J_URI")
    NEO4J_USER: str = Field(default="", validation_alias="NEO4J_USER")
    NEO4J_PASSWORD: str = Field(default="", validation_alias="NEO4J_PASSWORD")
    NEO4J_DATABASE: str = Field(default="neo4j", validation_alias="NEO4J_DATABASE")
    NEO4J_MAX_CONNECTION_POOL_SIZE: int = Field(default=100, validation_alias="NEO4J_MAX_CONNECTION_POOL_SIZE")
    NEO4J_CONNECTION_TIMEOUT_SECONDS: int = Field(default=15, validation_alias="NEO4J_CONNECTION_TIMEOUT_SECONDS")
    NEO4J_ENFORCE_TLS: bool = Field(default=True, validation_alias="NEO4J_ENFORCE_TLS")
    QUERY_CACHE_MAX_SIZE: int = Field(default=10000, validation_alias="QUERY_CACHE_MAX_SIZE")
    HOUSEKEEPING_INTERVAL_SECONDS: int = Field(default=3600, validation_alias="HOUSEKEEPING_INTERVAL_SECONDS")
    REDIS_URL: str = Field(
        default="",
        validation_alias="REDIS_URL"
    )
    REDIS_PASSWORD: str = Field(default="", validation_alias="REDIS_PASSWORD")
    FIRE_CROW_MOCK_SANDBOX: bool = Field(default=False, validation_alias="FIRE_CROW_MOCK_SANDBOX")
    FIRE_CROW_SCANNER_IMAGE: str = Field(
        default="ghcr.io/johan-droid/firecrow-scanner:2026-06-06",
        validation_alias="FIRE_CROW_SCANNER_IMAGE",
    )

    # --- GitHub Integrations ---
    GITHUB_CLIENT_ID: str = Field(default="", validation_alias="GITHUB_CLIENT_ID")
    GITHUB_CLIENT_SECRET: str = Field(default="", validation_alias="GITHUB_CLIENT_SECRET")
    GITHUB_TOKEN: str = Field(default="", validation_alias="GITHUB_TOKEN")

    # --- Google Integrations ---
    GOOGLE_CLIENT_ID: str = Field(default="", validation_alias="GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET: str = Field(default="", validation_alias="GOOGLE_CLIENT_SECRET")

    # --- Communication ---
    RESEND_API_KEY: str = Field(default="", validation_alias="RESEND_API_KEY")
    BREVO_API_KEY: str = Field(default="", validation_alias="BREVO_API_KEY")
    SENDER_EMAIL: str = Field(default="reports@firecrow.dev", validation_alias="SENDER_EMAIL")

    # --- Google/SMTP Mail ---
    SMTP_HOST: str = Field(default="smtp.gmail.com", validation_alias="SMTP_HOST")
    SMTP_PORT: int = Field(default=587, validation_alias="SMTP_PORT")
    SMTP_USER: str = Field(default="", validation_alias="SMTP_USER")
    SMTP_PASSWORD: str = Field(default="", validation_alias="SMTP_PASSWORD")

    # --- Report Storage (Cloudflare R2) ---
    R2_ACCESS_KEY_ID: str = Field(default="", validation_alias="R2_ACCESS_KEY_ID")
    R2_SECRET_ACCESS_KEY: str = Field(default="", validation_alias="R2_SECRET_ACCESS_KEY")
    R2_ENDPOINT_URL: str = Field(default="", validation_alias="R2_ENDPOINT_URL")
    R2_BUCKET_NAME: str = Field(default="firecrow-reports", validation_alias="R2_BUCKET_NAME")

    # --- AI Models API Keys ---
    GEMINI_API_KEY: str = Field(default="", validation_alias="GEMINI_API_KEY")
    GEMINI_MODEL: str = Field(default="gemini-1.5-flash", validation_alias="GEMINI_MODEL")
    # Backend base URL for absolute URLs (used in OAuth redirect URIs, etc.)
    BACKEND_BASE_URL: str = Field(default="https://firecrow-backend-ff41dd027fe1.herokuapp.com", validation_alias="BACKEND_BASE_URL")

    # --- Gemini Tuning ---
    GEMINI_FALLBACK_MODEL: str = Field(default="gemini-1.5-pro", validation_alias="GEMINI_FALLBACK_MODEL")
    GEMINI_ENABLE_FALLBACK_MODEL: bool = Field(default=True, validation_alias="GEMINI_ENABLE_FALLBACK_MODEL")
    GEMINI_MAX_ATTEMPTS: int = Field(default=3, validation_alias="GEMINI_MAX_ATTEMPTS")
    GEMINI_TIMEOUT_SECONDS: int = Field(default=30, validation_alias="GEMINI_TIMEOUT_SECONDS")
    GEMINI_MAX_FINDINGS_PER_CALL: int = Field(default=50, validation_alias="GEMINI_MAX_FINDINGS_PER_CALL")
    GEMINI_MAX_PROMPT_CHARS: int = Field(default=100000, validation_alias="GEMINI_MAX_PROMPT_CHARS")
    GEMINI_DAILY_SOFT_LIMIT: int = Field(default=1000, validation_alias="GEMINI_DAILY_SOFT_LIMIT")
    GEMINI_MIN_SECONDS_BETWEEN_CALLS: int = Field(default=1, validation_alias="GEMINI_MIN_SECONDS_BETWEEN_CALLS")

    # --- Orchestration Tunables ---
    MAX_ACTIVE_JOBS_PER_USER: int = Field(default=2, validation_alias="MAX_ACTIVE_JOBS_PER_USER")
    BROKER_CONNECTION_TIMEOUT: float = Field(default=0.5, validation_alias="BROKER_CONNECTION_TIMEOUT")
    SSE_POLL_INTERVAL: float = Field(default=0.5, validation_alias="SSE_POLL_INTERVAL")
    SSE_HEARTBEAT_INTERVAL: float = Field(default=15.0, validation_alias="SSE_HEARTBEAT_INTERVAL")
    REPORT_PRESIGNED_TTL: int = Field(default=900, validation_alias="REPORT_PRESIGNED_TTL")
    REPORT_LOCAL_FALLBACK: bool = Field(default=True, validation_alias="REPORT_LOCAL_FALLBACK")
    MAX_SCAN_DURATION: int = Field(default=1800, validation_alias="MAX_SCAN_DURATION")
    DEFAULT_BUDGET_USD: float = Field(default=1.0, validation_alias="DEFAULT_BUDGET_USD")
    SCANNER_COMMAND_TIMEOUT: int = Field(default=300, validation_alias="SCANNER_COMMAND_TIMEOUT")
    SCANNER_OUTPUT_MAX_LENGTH: int = Field(default=20000, validation_alias="SCANNER_OUTPUT_MAX_LENGTH")
    API_DISCOVERY_LIMIT: int = Field(default=30, validation_alias="API_DISCOVERY_LIMIT")
    GEMINI_FINDINGS_CHUNK_SIZE: int = Field(default=50, validation_alias="GEMINI_FINDINGS_CHUNK_SIZE")
    LLM_CHAT_ASSISTANT: bool = Field(default=False, validation_alias="LLM_CHAT_ASSISTANT")
    LLM_DASHBOARD_INSIGHT: bool = Field(default=False, validation_alias="LLM_DASHBOARD_INSIGHT")
    LLM_ATTACK_CHAIN_NAMING: bool = Field(default=False, validation_alias="LLM_ATTACK_CHAIN_NAMING")
    LLM_PR_DESCRIPTION: bool = Field(default=False, validation_alias="LLM_PR_DESCRIPTION")

    # --- Scoring Tunables ---
    SCORING_CRITICAL: float = Field(default=9.8, validation_alias="SCORING_CRITICAL")
    SCORING_HIGH: float = Field(default=8.5, validation_alias="SCORING_HIGH")
    SCORING_MEDIUM: float = Field(default=5.5, validation_alias="SCORING_MEDIUM")
    SCORING_LOW: float = Field(default=2.5, validation_alias="SCORING_LOW")
    SCORING_INFO: float = Field(default=0.0, validation_alias="SCORING_INFO")

    # --- Sandbox launch profiles config ---
    SANDBOX_PYTHON_IMAGE: str = Field(default="python:3.12-alpine", validation_alias="SANDBOX_PYTHON_IMAGE")
    SANDBOX_NODE_IMAGE: str = Field(default="node:20-alpine", validation_alias="SANDBOX_NODE_IMAGE")

    # --- Reporter Tuning ---
    REPORT_COMPACT_MODE: bool = Field(default=True, validation_alias="REPORT_COMPACT_MODE")
    REPORT_MAX_PAGES: int = Field(default=30, validation_alias="REPORT_MAX_PAGES")
    REPORT_MAX_FINDINGS_IN_PDF: int = Field(default=50, validation_alias="REPORT_MAX_FINDINGS_IN_PDF")
    REPORT_MAX_EVIDENCE_CHARS: int = Field(default=1200, validation_alias="REPORT_MAX_EVIDENCE_CHARS")
    REPORT_MAX_REMEDIATION_CHARS: int = Field(default=1200, validation_alias="REPORT_MAX_REMEDIATION_CHARS")
    REPORT_INCLUDE_DETAILED_FINDINGS: bool = Field(default=True, validation_alias="REPORT_INCLUDE_DETAILED_FINDINGS")
    REPORT_STORE_FULL_ARTIFACT_JSON: bool = Field(default=True, validation_alias="REPORT_STORE_FULL_ARTIFACT_JSON")
    REPORT_STORE_HTML_IN_DB: bool = Field(default=True, validation_alias="REPORT_STORE_HTML_IN_DB")
    REPORT_STORE_MARKDOWN_IN_DB: bool = Field(default=True, validation_alias="REPORT_STORE_MARKDOWN_IN_DB")
    REPORT_EMAIL_ATTACH_PDF: bool = Field(default=True, validation_alias="REPORT_EMAIL_ATTACH_PDF")
    REPORT_TEMP_DIR: str = Field(default="", validation_alias="REPORT_TEMP_DIR")
    REPORT_DELETE_TEMP_PDF: bool = Field(default=True, validation_alias="REPORT_DELETE_TEMP_PDF")
    OPENAI_API_KEY: str = Field(default="", validation_alias="OPENAI_API_KEY")

    model_config = SettingsConfigDict(
        env_file=(
            WORKSPACE_DIR / ".env",
            WORKSPACE_DIR / ".env.local",
        ),
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @field_validator("GITHUB_OAUTH_SCOPES", mode="before")
    @classmethod
    def parse_github_oauth_scopes(cls, value: Any) -> list[str]:
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]

        if value is None:
            return ["repo", "workflow", "read:org", "user:email"]

        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                return ["repo", "workflow", "read:org", "user:email"]

            if raw.startswith("["):
                parsed = json.loads(raw)
                if not isinstance(parsed, list):
                    raise ValueError("GITHUB_OAUTH_SCOPES JSON value must be a list.")
                return [str(item).strip() for item in parsed if str(item).strip()]

            return [scope.strip() for scope in raw.split(",") if scope.strip()]

        raise ValueError("Unsupported GITHUB_OAUTH_SCOPES value.")

    @model_validator(mode="after")
    def _ensure_frontend_url(self) -> "Settings":
        """Require ``FRONTEND_URL`` in production mode.
        The API must know which origin is allowed for CORS and CSRF redirects.
        """
        if not self.DEBUG and not self.FRONTEND_URL:
            import logging
            logger = logging.getLogger("firecrow.config")
            logger.warning("FRONTEND_URL is not set in production. CSRF and CORS might be restricted.")
        return self


# Global settings instance
settings = Settings()

_global_state: dict[str, bool] = {
    "r2_disabled": False
}

