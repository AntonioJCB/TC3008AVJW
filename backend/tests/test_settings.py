import os
import unittest
from unittest.mock import patch

from app.settings import Settings


class SettingsTests(unittest.TestCase):
    def test_crtsh_queda_habilitado_por_defecto_y_se_puede_desactivar(self) -> None:
        base = {
            "SUPABASE_URL": "https://example.supabase.co",
            "SUPABASE_SERVICE_ROLE_KEY": "server-secret",
        }
        with patch.dict(os.environ, base, clear=True):
            self.assertTrue(Settings.from_environment().crtsh_enabled)
        with patch.dict(os.environ, {**base, "CRTSH_ENABLED": "false"}, clear=True):
            self.assertFalse(Settings.from_environment().crtsh_enabled)

    def test_default_theharvester_restores_passive_hackertarget_source(self) -> None:
        with patch.dict(
            os.environ,
            {
                "SUPABASE_URL": "https://example.supabase.co",
                "SUPABASE_SERVICE_ROLE_KEY": "server-secret",
            },
            clear=True,
        ):
            self.assertEqual(
                Settings.from_environment().theharvester_sources,
                "certspotter,hackertarget,rapiddns,urlscan",
            )

    def test_llaves_incompatibles_dan_instrucciones_sin_exponer_el_secreto(self):
        for key, message in [("sb_publishable_prueba", "llave pública"), ("sb_secret_prueba", "legacy service_role")]:
            with self.subTest(key=key), patch.dict(os.environ, {
                "SUPABASE_URL": "https://example.supabase.co",
                "SUPABASE_SERVICE_ROLE_KEY": key,
            }, clear=True):
                with self.assertRaisesRegex(RuntimeError, message) as error:
                    Settings.from_environment()
                self.assertNotIn(key, str(error.exception))

    def test_web_requires_explicit_server_enablement(self) -> None:
        with patch.dict(
            os.environ,
            {
                "SUPABASE_URL": "https://example.supabase.co",
                "SUPABASE_SERVICE_ROLE_KEY": "server-secret",
                "WEB_ACTIVE_ENABLED": "false",
            },
            clear=True,
        ):
            self.assertFalse(Settings.from_environment().web_enabled)

    def test_service_role_placeholder_is_rejected(self) -> None:
        with patch.dict(
            os.environ,
            {
                "SUPABASE_URL": "https://example.supabase.co",
                "SUPABASE_SERVICE_ROLE_KEY": "replace-with-server-only-secret-key",
            },
            clear=True,
        ):
            with self.assertRaisesRegex(RuntimeError, "SUPABASE_SERVICE_ROLE_KEY"):
                Settings.from_environment()


if __name__ == "__main__":
    unittest.main()
