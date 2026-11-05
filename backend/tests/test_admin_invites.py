"""La invitación solo puede iniciarla un administrador de plataforma activo."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient

from app import main


URL = "/api/admin/clientes/00000000-0000-0000-0000-000000000001/usuarios/invitar"
BODY = {"nombre": "Cuenta nueva", "correo": "nueva@example.com", "rol": "lector"}


def test_no_admin_cannot_invite():
    main.app.dependency_overrides[main._current_user] = lambda: SimpleNamespace(id="user-1")
    try:
        with patch.object(main, "_supabase_client", return_value=MagicMock()), \
             patch.object(main, "_execute", side_effect=[{"esta_activo": True}, None]), \
             patch.object(main, "run_in_threadpool", new_callable=AsyncMock) as invite:
            response = TestClient(main.app).post(URL, json=BODY)
        assert response.status_code == 403
        invite.assert_not_awaited()
    finally:
        main.app.dependency_overrides.clear()


def test_active_platform_admin_invites_and_assigns():
    main.app.dependency_overrides[main._current_user] = lambda: SimpleNamespace(id="user-1")
    try:
        invitation = SimpleNamespace(user=SimpleNamespace(id="invited-1"))
        with patch.object(main, "_supabase_client", return_value=MagicMock()), \
             patch.object(main, "_execute", side_effect=[
                 {"esta_activo": True}, {"usuario_id": "user-1"},
                 {"esta_activa": True, "archivada_en": None}, [{"id": "invited-1"}], [{}],
             ]), \
             patch.object(main, "get_settings", return_value=SimpleNamespace(frontend_url="http://localhost:5173")), \
             patch.object(main, "run_in_threadpool", new_callable=AsyncMock, return_value=invitation) as invite:
            response = TestClient(main.app).post(URL, json=BODY)
        assert response.status_code == 201
        assert response.json() == {"id": "invited-1"}
        assert invite.await_args.args[1] == "nueva@example.com"
        assert invite.await_args.args[2]["redirect_to"].endswith("/restablecer-clave")
    finally:
        main.app.dependency_overrides.clear()
