# Copyright 2026 Marcus Furlong <furlongm@gmail.com>
#
# This file is part of Patchman.
#
# Patchman is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 only.
#
# Patchman is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Patchman. If not, see <http://www.gnu.org/licenses/>

from unittest.mock import Mock, patch

from django.contrib.auth.models import User
from django.test import override_settings
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_api_key.models import APIKey

from hosts.models import Host
from reports.models import Report
from security.models import CVE


@override_settings(
    REQUIRE_API_KEY=False,
    CELERY_TASK_ALWAYS_EAGER=True,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
)
class OperationsAPITests(APITestCase):
    def setUp(self):
        self.url = '/api/operations/'
        self.user = User.objects.create_user(username='ops', password='ops-pass')
        self.client.force_authenticate(user=self.user)

    def test_requires_authentication(self):
        self.client.force_authenticate(user=None)
        response = self.client.post(self.url, {'operation': 'process_reports'}, format='json')
        self.assertIn(response.status_code, [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN])

    def test_invalid_operation_returns_400(self):
        response = self.client.post(self.url, {'operation': 'nope'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['status'], 'error')

    @patch('util.api_views.refresh_repos')
    def test_refresh_repos_queues_all(self, mock_refresh_repos):
        mock_refresh_repos.delay.return_value = Mock(id='task-refresh-all')

        response = self.client.post(
            self.url,
            {'operation': 'refresh_repos', 'params': {'force': True}},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(response.data['operation'], 'refresh_repos')
        self.assertEqual(response.data['task_ids'], ['task-refresh-all'])
        mock_refresh_repos.delay.assert_called_once_with(True)

    @patch('util.api_views.find_all_host_updates')
    def test_host_updates_queues_all(self, mock_find_all):
        mock_find_all.delay.return_value = Mock(id='task-host-updates')

        response = self.client.post(self.url, {'operation': 'host_updates'}, format='json')

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(response.data['task_ids'], ['task-host-updates'])
        mock_find_all.delay.assert_called_once_with()

    @patch('util.api_views.find_all_host_updates_homogenous')
    def test_host_updates_alt_queues_task(self, mock_find_alt):
        mock_find_alt.delay.return_value = Mock(id='task-host-updates-alt')

        response = self.client.post(self.url, {'operation': 'host_updates_alt'}, format='json')

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(response.data['task_ids'], ['task-host-updates-alt'])
        mock_find_alt.delay.assert_called_once_with()

    @patch('util.api_views.process_reports')
    def test_process_reports_queues_task(self, mock_process_reports):
        mock_process_reports.delay.return_value = Mock(id='task-process-reports')

        response = self.client.post(self.url, {'operation': 'process_reports'}, format='json')

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(response.data['task_ids'], ['task-process-reports'])
        mock_process_reports.delay.assert_called_once_with()

    @patch('util.api_views.get_object_or_404')
    @patch('util.api_views.Report')
    @patch('util.api_views.process_report')
    def test_process_reports_with_hostname_queues_reports(self, mock_process_report, mock_report_model, mock_get_object_or_404):
        mock_get_object_or_404.return_value = Mock(id=1, hostname='server1.example.com')
        report1 = Mock(id=1)
        report2 = Mock(id=2)
        mock_report_model.objects.filter.return_value = [report1, report2]
        mock_process_report.delay.side_effect = [
            Mock(id='task-report-1'),
            Mock(id='task-report-2'),
        ]

        response = self.client.post(
            self.url,
            {'operation': 'process_reports', 'params': {'host': 'server1.example.com'}},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(len(response.data['task_ids']), 2)
        self.assertEqual(response.data['task_ids'], ['task-report-1', 'task-report-2'])
        self.assertEqual(mock_process_report.delay.call_count, 2)
        mock_report_model.objects.filter.assert_called_once_with(processed=False, host='server1.example.com')

    def test_process_reports_with_nonexistent_hostname_returns_404(self):
        response = self.client.post(
            self.url,
            {'operation': 'process_reports', 'params': {'host': 'nonexistent.example.com'}},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_process_reports_invalid_hostname_type_returns_400(self):
        response = self.client.post(
            self.url,
            {'operation': 'process_reports', 'params': {'host': 123}},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['status'], 'error')

    @patch('util.api_views.clean_database')
    def test_dbcheck_remove_duplicates_flag(self, mock_clean_database):
        mock_clean_database.delay.return_value = Mock(id='task-dbcheck')

        response = self.client.post(
            self.url,
            {'operation': 'dbcheck', 'params': {'remove_duplicates': True}},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(response.data['task_ids'], ['task-dbcheck'])
        mock_clean_database.delay.assert_called_once_with(remove_duplicate_packages=True)

    @patch('util.api_views.update_errata_task')
    def test_update_errata_queues_task(self, mock_update_errata):
        mock_update_errata.delay.return_value = Mock(id='task-update-errata')

        response = self.client.post(
            self.url,
            {'operation': 'update_errata', 'params': {'erratum_type': 'ubuntu', 'force': False}},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(response.data['task_ids'], ['task-update-errata'])
        mock_update_errata.delay.assert_called_once_with(
            erratum_type='ubuntu',
            force=False,
            repo=None,
        )

    def test_update_errata_invalid_type_returns_400(self):
        response = self.client.post(
            self.url,
            {'operation': 'update_errata', 'params': {'erratum_type': 'invalid'}},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['status'], 'error')

    @patch('util.api_views.update_cves')
    def test_update_all_cves_queues_task(self, mock_update_cves):
        mock_update_cves.delay.return_value = Mock(id='task-update-cves')

        response = self.client.post(self.url, {'operation': 'update_cves'}, format='json')

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(response.data['task_ids'], ['task-update-cves'])
        mock_update_cves.delay.assert_called_once_with()

    @patch('util.api_views.update_cve')
    def test_update_single_cve_queues_task(self, mock_update_cve):
        mock_update_cve.delay.return_value = Mock(id='task-update-cve')
        cve = CVE.objects.create(cve_id='CVE-2026-1234')

        response = self.client.post(
            self.url,
            {'operation': 'update_cves', 'params': {'cve_id': cve.cve_id}},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(response.data['task_ids'], ['task-update-cve'])
        mock_update_cve.delay.assert_called_once_with(cve.id)

    def test_update_single_cve_not_found_returns_404(self):
        response = self.client.post(
            self.url,
            {'operation': 'update_cves', 'params': {'cve_id': 'CVE-2099-9999'}},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


@override_settings(
    REQUIRE_API_KEY=True,
    CELERY_TASK_ALWAYS_EAGER=True,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
)
class OperationsApiKeyAuthTests(APITestCase):
    def setUp(self):
        self.url = '/api/operations/'
        self.api_key_obj, self.api_key = APIKey.objects.create_key(name='ops-key')

    @patch('util.api_views.process_reports')
    def test_valid_api_key_is_required_and_accepted(self, mock_process_reports):
        mock_process_reports.delay.return_value = Mock(id='task-process-reports')
        self.client.credentials(HTTP_AUTHORIZATION=f'Api-Key {self.api_key}')

        response = self.client.post(self.url, {'operation': 'process_reports'}, format='json')

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        mock_process_reports.delay.assert_called_once_with()

    def test_missing_api_key_is_rejected(self):
        response = self.client.post(self.url, {'operation': 'process_reports'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_invalid_api_key_is_rejected(self):
        self.client.credentials(HTTP_AUTHORIZATION='Api-Key invalid_key')
        response = self.client.post(self.url, {'operation': 'process_reports'}, format='json')
        self.assertIn(response.status_code, [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN])

    def test_revoked_api_key_is_rejected(self):
        self.api_key_obj.revoked = True
        self.api_key_obj.save()
        self.client.credentials(HTTP_AUTHORIZATION=f'Api-Key {self.api_key}')

        response = self.client.post(self.url, {'operation': 'process_reports'}, format='json')
        self.assertIn(response.status_code, [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN])

    def test_session_auth_only_is_not_sufficient_when_api_key_required(self):
        user = User.objects.create_user(username='session-user', password='password')
        self.client.force_authenticate(user=user)

        response = self.client.post(self.url, {'operation': 'process_reports'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
