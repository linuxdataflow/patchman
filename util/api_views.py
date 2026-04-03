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

from django.conf import settings
from django.shortcuts import get_object_or_404
from rest_framework import status, viewsets
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_api_key.permissions import HasAPIKey

from errata.tasks import update_errata as update_errata_task
from hosts.models import Host
from hosts.tasks import (
    find_all_host_updates,
    find_all_host_updates_homogenous,
    find_host_updates,
)
from reports.models import Report
from reports.tasks import process_report, process_reports
from repos.tasks import refresh_repo, refresh_repos
from security.models import CVE
from security.tasks import update_cve, update_cves
from util.api_serializers import OperationRequestSerializer
from util.tasks import clean_database


class OperationViewSet(viewsets.ViewSet):
    """Queue asynchronous Patchman operations via Celery tasks."""

    def get_permissions(self):
        # Enforce API key auth for operations when explicitly enabled.
        if getattr(settings, 'REQUIRE_API_KEY', False):
            return [HasAPIKey()]
        return [IsAuthenticated()]

    def create(self, request):
        serializer = OperationRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {'status': 'error', 'errors': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )

        operation = serializer.validated_data['operation']
        params = serializer.validated_data.get('params', {})

        task_ids = []

        if operation == 'refresh_repos':
            task_ids = self._queue_refresh_repos(params)
        elif operation == 'host_updates':
            task_ids = self._queue_host_updates(params)
        elif operation == 'host_updates_alt':
            result = find_all_host_updates_homogenous.delay()
            task_ids.append(result.id)
        elif operation == 'process_reports':
            task_ids = self._queue_process_reports(params)
        elif operation == 'dbcheck':
            remove_duplicates = params.get('remove_duplicates', False)
            result = clean_database.delay(remove_duplicate_packages=remove_duplicates)
            task_ids.append(result.id)
        elif operation == 'update_errata':
            result = update_errata_task.delay(
                erratum_type=params.get('erratum_type'),
                force=params.get('force', False),
                repo=params.get('repo_id'),
            )
            task_ids.append(result.id)
        elif operation == 'update_cves':
            task_ids = self._queue_update_cves(params)

        return Response(
            {
                'status': 'accepted',
                'operation': operation,
                'task_ids': task_ids,
                'message': 'Operation queued for processing',
            },
            status=status.HTTP_202_ACCEPTED,
        )

    def _queue_refresh_repos(self, params):
        force = params.get('force', False)
        repo_id = params.get('repo_id')

        if repo_id is not None:
            result = refresh_repo.delay(repo_id, force)
            return [result.id]

        result = refresh_repos.delay(force)
        return [result.id]

    def _queue_host_updates(self, params):
        host = params.get('host')
        if host:
            host_obj = get_object_or_404(Host, hostname=host)
            result = find_host_updates.delay(host_obj.id)
            return [result.id]

        result = find_all_host_updates.delay()
        return [result.id]

    def _queue_process_reports(self, params):
        host = params.get('host')
        if host:
            # Validate host exists
            host_obj = get_object_or_404(Host, hostname=host)
            # Get all unprocessed reports for this host
            reports = Report.objects.filter(processed=False, host=host)
            task_ids = []
            for report in reports:
                result = process_report.delay(report.id)
                task_ids.append(result.id)
            return task_ids

        result = process_reports.delay()
        return [result.id]

    def _queue_update_cves(self, params):
        cve_id = params.get('cve_id')
        if cve_id:
            cve = get_object_or_404(CVE, cve_id=cve_id)
            result = update_cve.delay(cve.id)
            return [result.id]

        result = update_cves.delay()
        return [result.id]
