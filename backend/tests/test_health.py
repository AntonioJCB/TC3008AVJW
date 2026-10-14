from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from app.core.config import Settings, get_settings
from app.main import app
from app.services import health as health_service


def configured_database() -> Settings:
    return Settings(
        database_url="postgresql+psycopg://user:pass@localhost:5432/baxtersec",
        _env_file=None,
    )


def test_process_health_is_available_without_database() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_database_health_reports_missing_configuration() -> None:
    app.dependency_overrides[get_settings] = lambda: Settings(
        database_url=None, _env_file=None
    )
    try:
        with TestClient(app) as client:
            response = client.get("/api/v1/health/db")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 503
    assert response.json() == {"detail": "Database not configured"}


def test_database_health_reports_connection_failure(monkeypatch) -> None:
    class UnavailableEngine:
        def connect(self):
            raise OperationalError("SELECT 1", {}, Exception("connection failed"))

    monkeypatch.setattr(health_service, "get_engine", lambda _: UnavailableEngine())
    app.dependency_overrides[get_settings] = configured_database
    try:
        with TestClient(app) as client:
            response = client.get("/api/v1/health/db")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 503
    assert response.json() == {"detail": "Database unavailable"}


def test_database_health_reports_success(monkeypatch) -> None:
    class AvailableConnection:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def execute(self, statement):
            assert str(statement) == "SELECT 1"

    class AvailableEngine:
        def connect(self):
            return AvailableConnection()

    monkeypatch.setattr(health_service, "get_engine", lambda _: AvailableEngine())
    app.dependency_overrides[get_settings] = configured_database
    try:
        with TestClient(app) as client:
            response = client.get("/api/v1/health/db")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
