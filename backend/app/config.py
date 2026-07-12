import json
import os
from pathlib import Path
from typing import Annotated, Any, Literal
from pydantic_settings import BaseSettings, SettingsConfigDict, NoDecode
from pydantic import Field, field_validator, model_validator


BACKEND_DIR = Path(__file__).resolve().parents[1]
WORKSPACE_DIR = Path(__file__).resolve().parents[1]

_env_local = WORKSPACE_DIR / ".env.local"
_env_file = WORKSPACE_DIR / ".env"
try:
    from dotenv import load_dotenv
    load_dotenv(_env_local)
    load_dotenv(_env_file)
except ImportError:
    pass


class Settings(BaseSettings):
    @model_validator(mode="after")
    def _ensure_critical_secrets(self) -> "Settings":
        insecure_dev_values = {
            "", "dev_secret_key_change_in_production_1234567890", "change_me", "changeme",
            "secret", "development", "dev_only_firecrow_local_secret_key_32_bytes_minimum_DO_NOT_USE_IN_PRODUCTION",
            "local_dev_secret_key_change_me_1234567890", "local_dev_encryption_key_change_me_1234567890",
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
                raise ValueError("SECRET_KEY cannot use a known development value.")
            if len(self.SECRET_KEY) < 32:
                raise ValueError("SECRET_KEY must be at least 32 characters.")
            if not self.ENCRYPTION_KEY:
                object.__setattr__(self, "ENCRYPTION_KEY", self.SECRET_KEY)
            elif self.ENCRYPTION_KEY.strip() in insecure_dev_values or len(self.ENCRYPTION_KEY) < 32:
                raise ValueError("ENCRYPTION_KEY must be at least 32 characters and not a dev value.")

        if not self.DEBUG:
            if not self.SECRET_KEY:
                raise RuntimeError("Missing critical secrets for production: SECRET_KEY")
            if self.FIRE_CROW_SCANNER_IMAGE.endswith(":latest"):
                raise ValueError("FIRE_CROW_SCANNER_IMAGE must be pinned in production.")
            if not getattr(self, "REPORT_LOCAL_FALLBACK", True):
                if not self.R2_ACCESS_KEY_ID or not self.R2_SECRET_ACCESS_KEY or not self.R2_BUCKET_NAME or not self.R2_ENDPOINT_URL:
                    raise ValueError("Cloud storage configuration is missing, but REPORT_LOCAL_FALLBACK is False.")

        # Neo4j validation
        if not self.NEO4J_URI:
            raise ValueError("NEO4J_URI is required.")
        if not self.NEO4J_USER:
            raise ValueError("NEO4J_USER is required.")
        if not self.NEO4J_PASSWORD:
            raise ValueError("NEO4J_PASSWORD is required.")
        if len(self.NEO4J_PASSWORD) < 16:
            raise ValueError("NEO4J_PASSWORD must be at least 16 characters.")
        if self.NEO4J_PASSWORD.strip().lower() in {"password", "neo4j", "changeme", "change_me", "admin"}:
            raise ValueError("NEO4J_PASSWORD cannot use a default or known weak value.")
        if self.NEO4J_ENFORCE_TLS and not self.NEO4J_URI.startswith(("neo4j+s://", "bolt+s://")):
            local_prefixes = ("neo4j://localhost", "bolt://localhost", "neo4j://127.0.0.1", "bolt://127.0.0.1")
            if not any(self.NEO4J_URI.startswith(prefix) for prefix in local_prefixes):
                raise ValueError("NEO4J_URI must use TLS for non-local deployments when NEO4J_ENFORCE_TLS=true.")

        if self.REDIS_PASSWORD:
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(self.REDIS_URL)
            if parsed.scheme in ("redis", "rediss") and not parsed.password:
                netloc = parsed.netloc
                if "@" in netloc:
                    user_host = netloc.split("@", 1)
                    user, host = user_host[0], user_host[1]
                    if ":" not in user:
                        netloc = f"{user}:{self.REDIS_PASSWORD}@{host}"
                else:
                    netloc = f":{self.REDIS_PASSWORD}@{netloc}"
                object.__setattr__(self, "REDIS_URL", urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)))
        return self

    PORT: int = Field(default=8000)
    HOST: str = Field(default="0.0.0.0")
    DEBUG: bool = Field(default=False)
    SECRET_KEY: str = Field(default="")
    ENCRYPTION_KEY: str = Field(default="")
    FRONTEND_URL: str = Field(default="")
    CORS_ORIGINS: str = Field(default="")
    PRIVACY_POLICY_VERSION: str = Field(default="2026-06-06")
    TERMS_VERSION: str = Field(default="2026-06-06")
    GITHUB_OAUTH_SCOPES: Annotated[list[str], NoDecode] = Field(default=["repo", "workflow", "read:org", "user:email"])
    # Rate limiting configuration (hardcoded defaults)
    DEFAULT_RATE_LIMIT: str = Field(default="100/hour")  # Default rate limit when DEBUG=False
    TENANT_LIST_RATE_LIMIT: str = Field(default="20/minute")
    TENANT_CREATE_RATE_LIMIT: str = Field(default="10/minute")
    TENANT_GET_RATE_LIMIT: str = Field(default="30/minute")
    TENANT_UPDATE_RATE_LIMIT: str = Field(default="20/minute")
    TENANT_DELETE_RATE_LIMIT: str = Field(default="20/minute")
    TENANT_MEMBERS_RATE_LIMIT: str = Field(default="10/minute")
    TENANT_INVITE_RATE_LIMIT: str = Field(default="10/minute")
    TENANT_REVOKE_INVITE_RATE_LIMIT: str = Field(default="20/minute")
    LEADERBOARD_RATE_LIMIT: str = Field(default="20/minute")
    CHAT_RATE_LIMIT: str = Field(default="20/minute")
    PAM_REQUEST_RATE_LIMIT: str = Field(default="10/minute")
    PAM_LIST_RATE_LIMIT: str = Field(default="20/minute")
    PAM_APPROVE_RATE_LIMIT: str = Field(default="20/minute")
    PAM_REJECT_RATE_LIMIT: str = Field(default="20/minute")
    PAM_CANCEL_RATE_LIMIT: str = Field(default="10/minute")
    PAM_REVOKE_RATE_LIMIT: str = Field(default="10/minute")
    PAM_SESSIONS_RATE_LIMIT: str = Field(default="20/minute")
    PAM_ACTIVITY_RATE_LIMIT: str = Field(default="10/minute")
    PAM_POLICY_RATE_LIMIT: str = Field(default="5/minute")
    PAM_CONFIG_RATE_LIMIT: str = Field(default="20/minute")
    IAM_IDENTITIES_RATE_LIMIT: str = Field(default="20/minute")
    IAM_CREDENTIALS_RATE_LIMIT: str = Field(default="10/minute")
    IAM_PERMISSIONS_RATE_LIMIT: str = Field(default="10/minute")
    IAM_ROLES_RATE_LIMIT: str = Field(default="20/minute")
    IAM_POLICIES_RATE_LIMIT: str = Field(default="10/minute")
    IAM_ATTACH_ROLE_RATE_LIMIT: str = Field(default="10/minute")
    IAM_DETACH_ROLE_RATE_LIMIT: str = Field(default="10/minute")
    IAM_ACTIVATE_ROLE_RATE_LIMIT: str = Field(default="10/minute")
    IAM_DEACTIVATE_ROLE_RATE_LIMIT: str = Field(default="5/minute")
    IAM_KEYS_RATE_LIMIT: str = Field(default="20/minute")
    IAM_ROTATE_KEY_RATE_LIMIT: str = Field(default="10/minute")
    IAM_REVOKE_KEY_RATE_LIMIT: str = Field(default="10/minute")
    IAM_DORMANT_SCAN_RATE_LIMIT: str = Field(default="10/minute")
    IAM_SHARED_ACCOUNT_SCAN_RATE_LIMIT: str = Field(default="10/minute")
    IAM_EXCESSIVE_PERMS_RATE_LIMIT: str = Field(default="20/minute")
    SYSTEM_HEALTH_RATE_LIMIT: str = Field(default="30/minute")
    SYSTEM_METRICS_RATE_LIMIT: str = Field(default="10/minute")
    SYSTEM_LOGS_RATE_LIMIT: str = Field(default="5/minute")
    SYSTEM_CONFIG_RATE_LIMIT: str = Field(default="20/minute")
    VERIFY_DOMAIN_RATE_LIMIT: str = Field(default="20/minute")
    VERIFY_CHALLENGSE_RATE_LIMIT: str = Field(default="10/minute")
    VERIFY_STATUS_RATE_LIMIT: str = Field(default="10/minute")
    VERIFY_DELETE_RATE_LIMIT: str = Field(default="10/minute")
    PUSH_REGISTER_RATE_LIMIT: str = Field(default="30/minute")
    PUSH_UNREGISTER_RATE_LIMIT: str = Field(default="20/minute")
    STORAGE_UPLOAD_RATE_LIMIT: str = Field(default="20/minute")
    STORAGE_DOWNLOAD_RATE_LIMIT: str = Field(default="10/minute")
    HEALTH_CHECK_RATE_LIMIT: str = Field(default="5/minute")
    AUDIT_SUBMIT_RATE_LIMIT: str = Field(default="10/minute")
    AUDIT_STATUS_RATE_LIMIT: str = Field(default="30/minute")
    AUDIT_RESULTS_RATE_LIMIT: str = Field(default="30/minute")
    AUDIT_CANCEL_RATE_LIMIT: str = Field(default="10/minute")
    AUDIT_FINDINGS_RATE_LIMIT: str = Field(default="15/minute")
    AUDIT_REPORT_RATE_LIMIT: str = Field(default="5/minute")
    AUDIT_EVIDENCE_RATE_LIMIT: str = Field(default="20/minute")
    AUDIT_ATTACK_CHAINS_RATE_LIMIT: str = Field(default="20/minute")
    SSE_CONNECT_RATE_LIMIT: str = Field(default="30/minute")
    AUTH_LOGIN_RATE_LIMIT: str = Field(default="20/minute")
    AUTH_REGISTER_RATE_LIMIT: str = Field(default="10/minute")
    AUTH_REFRESH_RATE_LIMIT: str = Field(default="30/minute")
    AUTH_LOGOUT_RATE_LIMIT: str = Field(default="30/minute")
    AUTH_PASSWORD_RESET_REQUEST_RATE_LIMIT: str = Field(default="20/minute")
    AUTH_PASSWORD_RESET_CONFIRM_RATE_LIMIT: str = Field(default="60/minute")
    AUTH_PASSWORD_CHANGE_RATE_LIMIT: str = Field(default="60/minute")
    AUTH_VERIFY_EMAIL_RATE_LIMIT: str = Field(default="30/minute")
    AUTH_RESEND_VERIFICATION_RATE_LIMIT: str = Field(default="10/minute")
    AUTH_OAUTH_CALLBACK_RATE_LIMIT: str = Field(default="20/minute")
    MFA_ENABLE_RATE_LIMIT: str = Field(default="5/minute")
    MFA_DISABLE_RATE_LIMIT: str = Field(default="10/minute")
    MFA_VERIFY_RATE_LIMIT: str = Field(default="10/minute")
    MFA_RECOVERY_RATE_LIMIT: str = Field(default="3/minute")
    MFA_REGENERATE_RECOVERY_RATE_LIMIT: str = Field(default="2/minute")
    MFA_TRUST_DEVICE_RATE_LIMIT: str = Field(default="3/minute")
    MFA_DEVICES_RATE_LIMIT: str = Field(default="20/minute")
    MFA_SET_DEFAULT_RATE_LIMIT: str = Field(default="10/minute")
    MFA_BACKUP_CODES_RATE_LIMIT: str = Field(default="5/minute")
    USER_PROFILE_RATE_LIMIT: str = Field(default="5/minute")
    USER_UPDATE_PROFILE_RATE_LIMIT: str = Field(default="2/minute")
    SSO_PROVIDERS_RATE_LIMIT: str = Field(default="20/minute")
    SSO_CONNECT_RATE_LIMIT: str = Field(default="10/minute")
    SSO_CALLBACK_RATE_LIMIT: str = Field(default="20/minute")
    SSO_DISCONNECT_RATE_LIMIT: str = Field(default="10/minute")
    SSO_SETTINGS_RATE_LIMIT: str = Field(default="10/minute")
    SSO_SYNC_RATE_LIMIT: str = Field(default="10/minute")
    SSO_PROVISION_RATE_LIMIT: str = Field(default="20/minute")
    SSO_DEPROVISION_RATE_LIMIT: str = Field(default="10/minute")
    SSO_AUDIT_LOGS_RATE_LIMIT: str = Field(default="20/minute")
    ROOT_INFO_RATE_LIMIT: str = Field(default="10/minute")
    ROOT_ECHO_RATE_LIMIT: str = Field(default="10/minute")
    ROOT_DISCOVER_RATE_LIMIT: str = Field(default="30/minute")
    ROOT_ANALYZE_RATE_LIMIT: str = Field(default="30/minute")
    
    LOGIN_FAILURE_WINDOW_MINUTES: int = Field(default=10)
    LOGIN_FAILURE_LIMIT: int = Field(default=5)
    MIN_PASSWORD_LENGTH: int = Field(default=12)
    MAX_REQUEST_BODY_BYTES: int = Field(default=10 * 1024 * 1024)
    MAX_JSON_BODY_BYTES: int = Field(default=2 * 1024 * 1024)
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=60)
    AUTH_COOKIE_NAME: str = Field(default="fc_access_token")
    AUTH_COOKIE_SECURE: bool = Field(default=True)
    AUTH_COOKIE_HTTPONLY: bool = Field(default=True)
    AUTH_COOKIE_SAMESITE: Literal['lax', 'strict', 'none'] | None = Field(default="strict")
    CSRF_ENABLED: bool = Field(default=True)
    MFA_ENFORCE_FOR_ADMINS: bool = Field(default=True)
    MFA_TOTP_ISSUER: str = Field(default="Fire Crow")
    MFA_MAX_FAILED_ATTEMPTS: int = Field(default=5)
    MFA_RECOVERY_CODE_COUNT: int = Field(default=8)
    SSO_OIDC_SCOPES: str = Field(default="openid email profile")
    SSO_ALLOW_AUTO_PROVISION: bool = Field(default=False)
    SSO_DEFAULT_ROLE_ID: str = Field(default="")
    PAM_MAX_DURATION_MINUTES: int = Field(default=480)
    PAM_MIN_DURATION_MINUTES: int = Field(default=1)
    PAM_MAX_PENDING_REQUESTS: int = Field(default=3)
    PAM_CLEANUP_INTERVAL_MINUTES: int = Field(default=15)
    IAM_DORMANT_DAYS_THRESHOLD: int = Field(default=90)
    IAM_SHARED_ACCOUNT_IP_THRESHOLD: int = Field(default=5)
    IAM_SERVICE_TOKEN_PREFIX: str = Field(default="fc_svc_")
    DATABASE_BACKEND: Literal["neo4j"] = Field(default="neo4j")
    DATABASE_URL: str = Field(default="")
    DATABASE_POOL_SIZE: int = Field(default=10)
    DATABASE_POOL_TIMEOUT: int = Field(default=30)
    DATABASE_POOL_RECYCLE: int = Field(default=3600)
    NEO4J_URI: str = Field(default="")
    NEO4J_USER: str = Field(default="")
    NEO4J_PASSWORD: str = Field(default="")
    NEO4J_DATABASE: str = Field(default="neo4j")
    NEO4J_MAX_CONNECTION_POOL_SIZE: int = Field(default=100)
    NEO4J_CONNECTION_TIMEOUT_SECONDS: int = Field(default=15)
    NEO4J_ENFORCE_TLS: bool = Field(default=True)
    QUERY_CACHE_MAX_SIZE: int = Field(default=10000)
    HOUSEKEEPING_INTERVAL_SECONDS: int = Field(default=3600)
    REDIS_URL: str = Field(default="")
    REDIS_PASSWORD: str = Field(default="")
    FIRE_CROW_MOCK_SANDBOX: bool = Field(default=False)
    FIRE_CROW_SCANNER_IMAGE: str = Field(default="ghcr.io/johan-droid/firecrow-scanner:2026-06-06")
    GITHUB_CLIENT_ID: str = Field(default="")
    GITHUB_CLIENT_SECRET: str = Field(default="")
    GITHUB_TOKEN: str = Field(default="")
    GOOGLE_CLIENT_ID: str = Field(default="")
    GOOGLE_CLIENT_SECRET: str = Field(default="")
    RESEND_API_KEY: str = Field(default="")
    BREVO_API_KEY: str = Field(default="")
    SENDER_EMAIL: str = Field(default="reports@firecrow.dev")
    SMTP_HOST: str = Field(default="smtp.gmail.com")
    SMTP_PORT: int = Field(default=587)
    SMTP_USER: str = Field(default="")
    SMTP_PASSWORD: str = Field(default="")
    R2_ACCESS_KEY_ID: str = Field(default="")
    R2_SECRET_ACCESS_KEY: str = Field(default="")
    R2_ENDPOINT_URL: str = Field(default="")
    R2_BUCKET_NAME: str = Field(default="firecrow-reports")
    GEMINI_API_KEY: str = Field(default="")
    GEMINI_MODEL: str = Field(default="gemini-1.5-flash")
    BACKEND_BASE_URL: str = Field(default="")
    GEMINI_FALLBACK_MODEL: str = Field(default="gemini-1.5-pro")
    GEMINI_ENABLE_FALLBACK_MODEL: bool = Field(default=True)
    GEMINI_MAX_ATTEMPTS: int = Field(default=3)
    GEMINI_TIMEOUT_SECONDS: int = Field(default=30)
    GEMINI_MAX_FINDINGS_PER_CALL: int = Field(default=50)
    GEMINI_MAX_PROMPT_CHARS: int = Field(default=100000)
    GEMINI_DAILY_SOFT_LIMIT: int = Field(default=1000)
    GEMINI_MIN_SECONDS_BETWEEN_CALLS: int = Field(default=1)
    MAX_ACTIVE_JOBS_PER_USER: int = Field(default=2)
    BROKER_CONNECTION_TIMEOUT: float = Field(default=0.5)
    SSE_POLL_INTERVAL: float = Field(default=0.5)
    SSE_HEARTBEAT_INTERVAL: float = Field(default=15.0)
    REPORT_PRESIGNED_TTL: int = Field(default=900)
    REPORT_LOCAL_FALLBACK: bool = Field(default=True)
    MAX_SCAN_DURATION: int = Field(default=1800)
    DEFAULT_BUDGET_USD: float = Field(default=1.0)
    SCANNER_COMMAND_TIMEOUT: int = Field(default=300)
    SCANNER_OUTPUT_MAX_LENGTH: int = Field(default=20000)
    API_DISCOVERY_LIMIT: int = Field(default=30)
    GEMINI_FINDINGS_CHUNK_SIZE: int = Field(default=50)
    LLM_CHAT_ASSISTANT: bool = Field(default=False)
    LLM_DASHBOARD_INSIGHT: bool = Field(default=False)
    LLM_ATTACK_CHAIN_NAMING: bool = Field(default=False)
    LLM_PR_DESCRIPTION: bool = Field(default=False)
    SCORING_CRITICAL: float = Field(default=9.8)
    SCORING_HIGH: float = Field(default=8.5)
    SCORING_MEDIUM: float = Field(default=5.5)
    SCORING_LOW: float = Field(default=2.5)
    SCORING_INFO: float = Field(default=0.0)
    SANDBOX_PYTHON_IMAGE: str = Field(default="python:3.12-alpine")
    SANDBOX_NODE_IMAGE: str = Field(default="node:20-alpine")
    REPORT_COMPACT_MODE: bool = Field(default=True)
    REPORT_MAX_PAGES: int = Field(default=30)
    REPORT_MAX_FINDINGS_IN_PDF: int = Field(default=50)
    REPORT_MAX_EVIDENCE_CHARS: int = Field(default=1200)
    REPORT_MAX_REMEDIATION_CHARS: int = Field(default=1200)
    REPORT_INCLUDE_DETAILED_FINDINGS: bool = Field(default=True)
    REPORT_STORE_FULL_ARTIFACT_JSON: bool = Field(default=True)
    REPORT_STORE_HTML_IN_DB: bool = Field(default=True)
    REPORT_STORE_MARKDOWN_IN_DB: bool = Field(default=True)
    REPORT_EMAIL_ATTACH_PDF: bool = Field(default=True)
    REPORT_TEMP_DIR: str = Field(default="")
    REPORT_DELETE_TEMP_PDF: bool = Field(default=True)
    OPENAI_API_KEY: str = Field(default="")

    model_config = SettingsConfigDict(env_file=(WORKSPACE_DIR / ".env", WORKSPACE_DIR / ".env.local"), env_file_encoding="utf-8", extra="ignore")

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
        if not self.DEBUG and not self.FRONTEND_URL:
            import logging
            logger = logging.getLogger("firecrow.config")
            logger.warning("FRONTEND_URL is not set in production. CSRF and CORS might be restricted.")
        return self


settings = Settings()
_global_state: dict[str, bool] = {"r2_disabled": False}
