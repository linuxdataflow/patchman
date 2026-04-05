# Copyright 2025 Marcus Furlong <furlongm@gmail.com>
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

import json
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.utils import timezone

from arch.models import MachineArchitecture
from domains.models import Domain
from hosts.models import Host
from operatingsystems.models import OSRelease, OSVariant
from reports.models import Report
from reports.tasks import (
    clean_host_reports, clean_reports, process_report, process_reports,
    remove_reports_with_no_hosts,
)


@override_settings(
    CELERY_TASK_ALWAYS_EAGER=True,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}}
)
class ProcessReportTaskTests(TestCase):
    """Tests for process_report Celery task."""

    def test_process_report_task_processes_report(self):
        """Test process_report task processes a report."""
        report = Report.objects.create(
            host='taskhost.example.com',
            domain='example.com',
            report_ip='192.168.1.100',
            os='Ubuntu 22.04.3 LTS',
            kernel='5.15.0-91-generic',
            arch='x86_64',
            protocol='2',
            packages=json.dumps([]),
            repos=json.dumps([]),
            modules=json.dumps([]),
            sec_updates=json.dumps([]),
            bug_updates=json.dumps([]),
        )
        self.assertFalse(report.processed)

        # Run the task directly (CELERY_TASK_ALWAYS_EAGER=True)
        process_report(report.id)

        report.refresh_from_db()
        self.assertTrue(report.processed)

    def test_process_report_task_creates_host(self):
        """Test process_report task creates Host."""
        report = Report.objects.create(
            host='newtaskhost.example.com',
            domain='example.com',
            report_ip='192.168.1.101',
            os='Ubuntu 22.04.3 LTS',
            kernel='5.15.0-91-generic',
            arch='x86_64',
            protocol='2',
            packages=json.dumps([]),
            repos=json.dumps([]),
            modules=json.dumps([]),
            sec_updates=json.dumps([]),
            bug_updates=json.dumps([]),
        )

        process_report(report.id)

        host = Host.objects.get(hostname='newtaskhost.example.com')
        self.assertIsNotNone(host)

    def test_process_report_task_skips_already_processed(self):
        """Test process_report skips already processed reports."""
        report = Report.objects.create(
            host='processedhost.example.com',
            domain='example.com',
            report_ip='192.168.1.102',
            os='Ubuntu 22.04.3 LTS',
            kernel='5.15.0-91-generic',
            arch='x86_64',
            protocol='2',
            processed=True,
            packages=json.dumps([]),
            repos=json.dumps([]),
            modules=json.dumps([]),
            sec_updates=json.dumps([]),
            bug_updates=json.dumps([]),
        )

        # Should not raise error
        process_report(report.id)
        report.refresh_from_db()
        self.assertTrue(report.processed)


@override_settings(
    CELERY_TASK_ALWAYS_EAGER=True,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}}
)
class ProcessReportsTaskTests(TestCase):
    """Tests for process_reports Celery task."""

    def test_process_reports_processes_unprocessed(self):
        """Test process_reports processes all unprocessed reports."""
        # Create multiple unprocessed reports
        for i in range(3):
            Report.objects.create(
                host=f'multihost{i}.example.com',
                domain='example.com',
                report_ip=f'192.168.1.{10 + i}',
                os='Ubuntu 22.04.3 LTS',
                kernel='5.15.0-91-generic',
                arch='x86_64',
                protocol='2',
                packages=json.dumps([]),
                repos=json.dumps([]),
                modules=json.dumps([]),
                sec_updates=json.dumps([]),
                bug_updates=json.dumps([]),
            )

        unprocessed_count = Report.objects.filter(processed=False).count()
        self.assertEqual(unprocessed_count, 3)

        # Run the task
        process_reports()

        # All should be processed now
        processed_count = Report.objects.filter(processed=True).count()
        self.assertEqual(processed_count, 3)

    def test_process_reports_ignores_processed(self):
        """Test process_reports ignores already processed reports."""
        Report.objects.create(
            host='alreadyprocessed.example.com',
            domain='example.com',
            report_ip='192.168.1.50',
            os='Ubuntu 22.04.3 LTS',
            kernel='5.15.0-91-generic',
            arch='x86_64',
            protocol='2',
            processed=True,
            packages=json.dumps([]),
            repos=json.dumps([]),
            modules=json.dumps([]),
            sec_updates=json.dumps([]),
            bug_updates=json.dumps([]),
        )

        # Should not raise error, just skip
        process_reports()


@override_settings(
    CELERY_TASK_ALWAYS_EAGER=True,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}}
)
class RemoveReportsWithNoHostsTaskTests(TestCase):
    """Tests for remove_reports_with_no_hosts Celery task."""

    def test_removes_orphan_reports(self):
        """Test task removes processed reports for non-existent hosts."""
        # Create a processed report for a host that doesn't exist
        Report.objects.create(
            host='nonexistent.example.com',
            domain='example.com',
            report_ip='192.168.1.99',
            os='Ubuntu 22.04.3 LTS',
            kernel='5.15.0-91-generic',
            arch='x86_64',
            protocol='2',
            processed=True,
            packages=json.dumps([]),
            repos=json.dumps([]),
            modules=json.dumps([]),
            sec_updates=json.dumps([]),
            bug_updates=json.dumps([]),
        )

        self.assertEqual(Report.objects.count(), 1)

        # Run the cleanup task
        remove_reports_with_no_hosts()

        # Report should be deleted
        self.assertEqual(Report.objects.count(), 0)

    def test_keeps_reports_with_existing_hosts(self):
        """Test task keeps reports for existing hosts."""
        # Create a host first
        arch = MachineArchitecture.objects.create(name='x86_64')
        osrelease = OSRelease.objects.create(name='Ubuntu 22.04')
        osvariant = OSVariant.objects.create(
            name='Ubuntu 22.04.3 LTS x86_64',
            osrelease=osrelease,
            arch=arch,
        )
        domain = Domain.objects.create(name='example.com')
        Host.objects.create(
            hostname='existinghost.example.com',
            ipaddress='192.168.1.200',
            arch=arch,
            osvariant=osvariant,
            domain=domain,
            lastreport=timezone.now(),
        )

        # Create a processed report for this host
        Report.objects.create(
            host='existinghost.example.com',
            domain='example.com',
            report_ip='192.168.1.200',
            os='Ubuntu 22.04.3 LTS',
            kernel='5.15.0-91-generic',
            arch='x86_64',
            protocol='2',
            processed=True,
            packages=json.dumps([]),
            repos=json.dumps([]),
            modules=json.dumps([]),
            sec_updates=json.dumps([]),
            bug_updates=json.dumps([]),
        )

        self.assertEqual(Report.objects.count(), 1)

        # Run the cleanup task
        remove_reports_with_no_hosts()

        # Report should still exist
        self.assertEqual(Report.objects.count(), 1)


@override_settings(
    CELERY_TASK_ALWAYS_EAGER=True,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}}
)
class CleanReportsTaskTests(TestCase):
    """Tests for clean_reports and clean_host_reports Celery tasks."""

    def setUp(self):
        self.arch = MachineArchitecture.objects.create(name='x86_64')
        self.osrelease = OSRelease.objects.create(name='Ubuntu 22.04')
        self.osvariant = OSVariant.objects.create(
            name='Ubuntu 22.04.3 LTS x86_64',
            osrelease=self.osrelease,
            arch=self.arch,
        )
        self.domain = Domain.objects.create(name='example.com')

    def _create_host(self, hostname, ip):
        return Host.objects.create(
            hostname=hostname,
            ipaddress=ip,
            arch=self.arch,
            osvariant=self.osvariant,
            domain=self.domain,
            lastreport=timezone.now(),
        )

    @patch('reports.tasks.remove_reports_with_no_hosts')
    @patch('reports.tasks.clean_host_reports')
    def test_clean_reports_queues_all_hosts(self, mock_clean_host_reports, mock_remove_reports):
        host1 = self._create_host('clean1.example.com', '192.168.1.210')
        host2 = self._create_host('clean2.example.com', '192.168.1.211')

        clean_reports()

        mock_clean_host_reports.delay.assert_any_call(host1.id)
        mock_clean_host_reports.delay.assert_any_call(host2.id)
        self.assertEqual(mock_clean_host_reports.delay.call_count, 2)
        mock_remove_reports.delay.assert_called_once_with()

    @patch('reports.tasks.clean_host_reports')
    def test_clean_reports_single_host_queues_single_task(self, mock_clean_host_reports):
        host = self._create_host('clean-single.example.com', '192.168.1.212')

        clean_reports(host_id=host.id)

        mock_clean_host_reports.delay.assert_called_once_with(host.id)

    def test_clean_host_reports_calls_model_cleanup(self):
        host = self._create_host('clean-model.example.com', '192.168.1.213')

        with patch.object(Host, 'clean_reports') as mock_clean_reports:
            clean_host_reports(host.id)

        mock_clean_reports.assert_called_once()

    def test_keeps_unprocessed_reports(self):
        """Test task keeps unprocessed reports even if host doesn't exist."""
        # Create an unprocessed report for a non-existent host
        Report.objects.create(
            host='pendinghost.example.com',
            domain='example.com',
            report_ip='192.168.1.98',
            os='Ubuntu 22.04.3 LTS',
            kernel='5.15.0-91-generic',
            arch='x86_64',
            protocol='2',
            processed=False,  # Not processed yet
            packages=json.dumps([]),
            repos=json.dumps([]),
            modules=json.dumps([]),
            sec_updates=json.dumps([]),
            bug_updates=json.dumps([]),
        )

        self.assertEqual(Report.objects.count(), 1)

        # Run the cleanup task
        remove_reports_with_no_hosts()

        # Report should still exist (not processed)
        self.assertEqual(Report.objects.count(), 1)
