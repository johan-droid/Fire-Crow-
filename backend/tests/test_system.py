from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.api.routes_auth import PRIVACY_POLICY_VERSION
from app.models import SessionLocal, User, get_db
from app.models.role import Role

client = TestClient(app)


def _register_user(username: str, role_name: str) -> tuple[dict[str, str], str]:
    import uuid
    from datetime import datetime, timezone
    from app.services.auth import create_access_token
    from app.config import settings

    db = SessionLocal()
    try:
        # Create Role and link to user in the DB
        role = db.query(Role).filter(Role.name == role_name).first()
        if not role:
            role = Role(
                name=role_name,
                description=f"Test role: {role_name}",
                can_start_scans=True,
                can_view_reports=True,
            )
            db.add(role)
            db.flush()

        user = db.query(User).filter(User.username == username).first()
        if not user:
            user = User(
                id=str(uuid.uuid4()),
                username=username,
                email=f"{username}@example.com",
                privacy_policy_version=PRIVACY_POLICY_VERSION,
                privacy_policy_accepted_at=datetime.now(timezone.utc),
                terms_version=settings.TERMS_VERSION,
                terms_accepted_at=datetime.now(timezone.utc),
                role_id=role.id,
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        else:
            user.role_id = role.id
            db.commit()
            db.refresh(user)

        token = create_access_token(user_id=user.id, username=user.username, db=db)
        user_id = user.id
    finally:
        db.close()
        
    return {"Authorization": f"Bearer {token}"}, user_id



def test_system_status_endpoint():
    headers, _ = _register_user("test_sys_status", "security_engineer")
    response = client.get("/api/v1/system/status", headers=headers)
    assert response.status_code == 200
    payload = response.json()
    assert payload["api"] == "online"
    # Integrations should not be in the response for non-admins
    assert "integrations" not in payload


def test_system_status_admin_endpoint():
    headers, _ = _register_user("test_sys_status_admin", "admin")
    response = client.get("/api/v1/system/status", headers=headers)
    assert response.status_code == 200
    payload = response.json()
    assert payload["api"] == "online"
    # Integrations should be in the response for admins
    assert "integrations" in payload


def test_database_stats_admin_required():
    # Test non-admin access (Forbidden)
    normal_headers, _ = _register_user("normal_user_stats", "security_engineer")
    response = client.get("/api/v1/system/database/stats", headers=normal_headers)
    assert response.status_code == 403
    assert response.json()["detail"] == "Administrative privileges required to access database management."

    # Test admin access (Success)
    admin_headers, _ = _register_user("admin_user_stats", "admin")
    response = client.get("/api/v1/system/database/stats", headers=admin_headers)
    assert response.status_code == 200
    payload = response.json()
    assert "dialect" in payload
    assert "row_counts" in payload
    assert "pending_migrations" in payload
    assert "users" in payload["row_counts"]


def test_database_housekeeping_admin_required():
    # Test non-admin access (Forbidden)
    normal_headers, _ = _register_user("normal_user_hk", "security_engineer")
    response = client.post("/api/v1/system/database/housekeeping", headers=normal_headers)
    assert response.status_code == 403

    # Test admin access (Success)
    admin_headers, _ = _register_user("admin_user_hk", "admin")
    response = client.post("/api/v1/system/database/housekeeping", headers=admin_headers)
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert "counts" in payload
    assert "pruned_logs" in payload["counts"]
