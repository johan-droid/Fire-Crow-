import os
import sys
import tempfile
from pathlib import Path

import pytest
from sqlalchemy.orm import close_all_sessions
from starlette.testclient import TestClient

# 1. Set environment variables at the very top to force a dedicated SQLite database for tests
# This must happen before any backend imports are triggered.
import uuid
TEST_DB_PATH = Path(tempfile.gettempdir()) / f"firecrow_pytest_{uuid.uuid4().hex}.db"

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB_PATH.as_posix()}"
os.environ["DATABASE_BACKEND"] = "postgresql"
os.environ["SECRET_KEY"] = "test_secret_key_32_bytes_minimum_value"
os.environ["ENCRYPTION_KEY"] = "test_encryption_key_32_bytes_minimum"
os.environ["DEBUG"] = "True"
os.environ["FIRE_CROW_MOCK_SANDBOX"] = "True"
os.environ["CSRF_ENABLED"] = "False"
os.environ["AUTH_COOKIE_SECURE"] = "True"
os.environ["AUTH_COOKIE_SAMESITE"] = "strict"

from app.services.limiter import limiter
limiter.enabled = False

from app.models.database import Base, engine


@pytest.fixture(autouse=True, scope="function")
def clear_test_client_cookies():
    for module in tuple(sys.modules.values()):
        client = getattr(module, "client", None)
        if isinstance(client, TestClient):
            client.cookies.clear()

    yield

    for module in tuple(sys.modules.values()):
        client = getattr(module, "client", None)
        if isinstance(client, TestClient):
            client.cookies.clear()


@pytest.fixture(autouse=True, scope="function")
def setup_test_db():
    """
    Ensure the test database schema is created before each test and dropped after.
    Since DATABASE_URL is set to a temp SQLite file, all imports use this database.
    """
    close_all_sessions()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    yield

    close_all_sessions()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(autouse=True, scope="session")
def cleanup_test_database():
    yield

    close_all_sessions()
    engine.dispose()
    if TEST_DB_PATH.exists():
        TEST_DB_PATH.unlink()
