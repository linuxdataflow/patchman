from unittest.mock import patch

from django.test import TestCase, override_settings

from errata.tasks import update_errata_full


@override_settings(
    CELERY_TASK_ALWAYS_EAGER=True,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}}
)
class ErrataTasksTests(TestCase):
    @patch('errata.tasks.enrich_errata')
    @patch('errata.tasks.mark_errata_security_updates')
    @patch('errata.tasks.scan_package_updates_for_affected_packages')
    @patch('errata.tasks.update_errata')
    def test_update_errata_full_runs_pipeline(self, mock_update_errata, mock_scan, mock_mark, mock_enrich):
        update_errata_full(erratum_type='ubuntu', force=True, repo=42)

        mock_update_errata.assert_called_once_with(erratum_type='ubuntu', force=True, repo=42)
        mock_scan.assert_called_once_with()
        mock_mark.assert_called_once_with()
        mock_enrich.assert_called_once_with()
