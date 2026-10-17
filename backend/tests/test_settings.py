import os
import unittest
from unittest.mock import patch

from app.settings import Settings


class SettingsTests(unittest.TestCase):
    def test_shodan_placeholder_is_not_treated_as_configured(self) -> None:
        with patch.dict(
            os.environ,
            {
                "SUPABASE_URL": "https://example.supabase.co",
                "SUPABASE_SERVICE_ROLE_KEY": "server-secret",
                "SHODAN_API_KEY": "replace-with-shodan-api-key",
            },
            clear=True,
        ):
            self.assertIsNone(Settings.from_environment().shodan_api_key)

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