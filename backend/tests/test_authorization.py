"""Regresiones de aislamiento entre organizaciones y autorización de escaneos."""

from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from app import main


@pytest.fixture
def client():
    return MagicMock()


def test_scan_de_otra_organizacion_no_es_visible(client):
    scan = {"id": "scan-1", "organizacion_id": "otra-org", "solicitado_por": "user-1"}
    with patch.object(main, "_execute", return_value=scan):
        with pytest.raises(HTTPException) as error:
            main._get_scan(client, "user-1", "mi-org", "scan-1", only_requester=False)
    assert error.value.status_code == 404


def test_solo_solicitante_puede_ejecutar_scan(client):
    scan = {"id": "scan-1", "organizacion_id": "mi-org", "solicitado_por": "user-2"}
    with patch.object(main, "_execute", return_value=scan):
        with pytest.raises(HTTPException) as error:
            main._get_scan(client, "user-1", "mi-org", "scan-1")
    assert error.value.status_code == 404


def test_usuario_inactivo_no_recibe_perfil(client):
    profile = {"organizacion_id": "mi-org", "rol": "admin", "esta_activo": False}
    with patch.object(main, "_execute", return_value=profile):
        with pytest.raises(HTTPException) as error:
            main._get_profile(client, "user-1", True)
    assert error.value.status_code == 403


@pytest.mark.parametrize("organization", [
    {"esta_activa": False, "archivada_en": None},
    {"esta_activa": False, "archivada_en": "2026-11-04T00:00:00Z"},
    None,
])
def test_organizacion_suspendida_no_permite_escaneos(client, organization):
    profile = {"organizacion_id": "mi-org", "rol": "admin", "esta_activo": True}
    with patch.object(main, "_execute", side_effect=[profile, organization]):
        with pytest.raises(HTTPException) as error:
            main._get_profile(client, "user-1", True)
    assert error.value.status_code == 403


def test_organizacion_activa_conserva_acceso(client):
    profile = {"organizacion_id": "mi-org", "rol": "analista", "esta_activo": True}
    organization = {"esta_activa": True, "archivada_en": None}
    with patch.object(main, "_execute", side_effect=[profile, organization]):
        assert main._get_profile(client, "user-1", True) == profile


def test_autorizacion_expirada_no_permite_scan(client):
    authorization = {
        "organizacion_id": "mi-org",
        "alcance": "example.com",
        "expira_en": "2000-01-01T00:00:00+00:00",
        "revocada_en": None,
    }
    scan = {"organizacion_id": "mi-org", "autorizacion_id": "auth-1"}
    with patch.object(main, "_execute", return_value=authorization):
        with pytest.raises(HTTPException) as error:
            main._authorized_domain(client, scan)
    assert error.value.status_code == 403


def test_autorizacion_requiere_dominio_principal_explicito(client):
    authorization = {
        "organizacion_id": "mi-org",
        "alcance": "*.example.com",
        "expira_en": None,
        "revocada_en": None,
    }
    scan = {"organizacion_id": "mi-org", "autorizacion_id": "auth-1"}
    with patch.object(main, "_execute", side_effect=[authorization, {"dominio_principal": "example.com"}]):
        with pytest.raises(HTTPException) as error:
            main._authorized_domain(client, scan)
    assert error.value.status_code == 403
