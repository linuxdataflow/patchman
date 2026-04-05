from unittest.mock import patch

from django.test import TestCase, override_settings

from security.tasks import refresh_cve_data, refresh_cwe_data


@override_settings(
    CELERY_TASK_ALWAYS_EAGER=True,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}}
)
class SecurityTasksTests(TestCase):
    @patch('security.tasks.refresh_cves_sync')
    def test_refresh_cve_data_forwards_args(self, mock_refresh_cves_sync):
        refresh_cve_data(cve_id='CVE-2026-0001', fetch_nist_data=True)
        mock_refresh_cves_sync.assert_called_once_with(cve_id='CVE-2026-0001', fetch_nist_data=True)

    @patch('security.tasks.refresh_cwes_sync')
    def test_refresh_cwe_data_forwards_args(self, mock_refresh_cwes_sync):
        refresh_cwe_data(cve_id='CVE-2026-0001')
        mock_refresh_cwes_sync.assert_called_once_with(cve_id='CVE-2026-0001')
