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

import hashlib
import ipaddress
from urllib.parse import urlencode, urlparse, urlsplit, urlunsplit

import requests
import redis
from django.conf import settings
from django.core.cache import cache
from django.shortcuts import get_object_or_404
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from rest_framework import status, viewsets
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle

from errata.tasks import update_errata as update_errata_task
from hosts.models import Host
from hosts.serializers import HostInventoryItemSerializer
from hosts.tasks import (
    find_all_host_updates,
    find_all_host_updates_homogenous,
    find_host_updates,
)
from reports.models import Report
from reports.tasks import process_report, process_reports
from repos.models import Repository
from repos.tasks import refresh_repo, refresh_repos
from security.models import CVE
from security.tasks import update_cve, update_cves
from patchman.celery import app as celery_app
from util.api_serializers import OperationRequestSerializer
from util.api_serializers import (
    HostInventoryHostgroupMutationSerializer,
    HostInventoryHostgroupSerializer,
)
from util.models import HostInventoryHostgroup
from util.permissions import HasAPIKeyOrIsAuthenticatedOrReadOnly
from util.tasks import clean_database


def _append_format_json(url):
    if not url:
        return ''
    if 'format=' in url:
        return url
    separator = '&' if '?' in url else '?'
    return f'{url}{separator}format=json'


def _normalize_rundeck_resources(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get('resources'), list):
        return data['resources']
    if isinstance(data, dict):
        resources = []
        for key, item in data.items():
            normalized = item or {}
            if not normalized.get('nodename'):
                normalized['nodename'] = key
            resources.append(normalized)
        return resources
    return []


def _normalize_hostname(value):
    host = str(value or '').strip().lower()
    if not host:
        return ''
    return host.rstrip('.')


def _build_resource_indexes(resources):
    by_name = {}
    by_short = {}
    by_ip = {}

    for resource in resources or []:
        node_name = _normalize_hostname(resource.get('nodename') or resource.get('hostname') or '')
        if node_name:
            by_name[node_name] = resource
            short_name = node_name.split('.', 1)[0]
            if short_name and short_name not in by_short:
                by_short[short_name] = resource

        resource_host = str(resource.get('hostname') or '').strip().lower()
        if resource_host and resource_host not in by_ip:
            by_ip[resource_host] = resource

    return {
        'by_name': by_name,
        'by_short': by_short,
        'by_ip': by_ip,
    }


def _resource_value(resource, keys):
    if not resource:
        return ''

    attrs = resource.get('attributes') if isinstance(resource.get('attributes'), dict) else {}
    for key in keys:
        value = resource.get(key)
        if value is None or value == '':
            value = attrs.get(key)
        if value is not None and value != '':
            return str(value).strip()
    return ''


def _normalize_provider(value):
    provider = str(value or '').strip().lower()
    if provider in {'gce', 'google', 'google-cloud', 'google cloud', 'google_compute_engine'}:
        return 'gcp'
    if provider in {'ms-azure', 'microsoft-azure'}:
        return 'azure'
    return provider or 'patchman'


def _normalize_gcp_zone(value):
    zone = str(value or '').strip()
    if not zone:
        return ''
    if '/' in zone:
        zone = zone.rstrip('/').split('/')[-1]
    return zone


def _region_from_zone(zone):
    zone_value = _normalize_gcp_zone(zone)
    if not zone_value:
        return ''
    if zone_value.count('-') >= 2:
        return '-'.join(zone_value.split('-')[:-1])
    return ''


def _normalize_gcp_location(value):
    location = str(value or '').strip()
    if not location:
        return ''
    if '/' in location:
        location = location.rstrip('/').split('/')[-1]

    # If the location is actually a zone, fold it to region so filtering remains stable.
    zone_region = _region_from_zone(location)
    if zone_region:
        return zone_region
    return location


def _normalize_azure_location(value):
    """Normalize Azure location (region) name. Handles resource-qualified paths and returns clean location."""
    location = str(value or '').strip()
    if not location:
        return ''
    if '/' in location:
        location = location.rstrip('/').split('/')[-1]
    return location


def _normalize_azure_zone(value):
    """Normalize Azure zone (numeric availability zone). Extracts zone number from zone qualifiers."""
    zone = str(value or '').strip()
    if not zone:
        return ''
    # Azure zones are usually single digits (1, 2, 3) or empty; handle resource-qualified paths
    if '/' in zone:
        zone = zone.rstrip('/').split('/')[-1]
    return zone


def _validate_rundeck_host(rundeck_host):
    """Validate and return the rundeck_host URL, or None if it is not allowed.

    Checks the incoming URL against ``settings.RUNDECK_HOST`` (an exact URL
    prefix allowlist entry).  If ``RUNDECK_HOST`` is not configured only
    ``http`` / ``https`` schemes are accepted and private / loopback / link-local
    / multicast / reserved / unspecified targets are rejected to prevent SSRF.
    """
    if not rundeck_host:
        return None
    clean = str(rundeck_host).rstrip('/')

    configured = str(getattr(settings, 'RUNDECK_HOST', '') or '').rstrip('/')
    if configured:
        if clean == configured:
            return clean
        return None

    # No allowlist configured — validate scheme and reject dangerous targets.
    try:
        parsed = urlparse(clean)
    except Exception:
        return None
    if parsed.scheme not in ('http', 'https'):
        return None
    hostname = parsed.hostname or ''
    try:
        addr = ipaddress.ip_address(hostname)
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        ):
            return None
    except ValueError:
        # Not an IP address — hostname-based URLs are allowed unless the host
        # looks like a well-known private name (localhost, etc.).
        if hostname.lower() in ('localhost',):
            return None
    return clean


def _get_rundeck_resources(rundeck_host, project, token):
    clean_host = _validate_rundeck_host(rundeck_host)
    if not clean_host:
        return []

    token_hash = hashlib.sha256(str(token or '').encode('utf-8')).hexdigest()[:12]
    cache_key = f'patchman:rundeck-resources:{clean_host}:{project}:{token_hash}'
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    project_name = project or 'patchman'
    url = f'{clean_host}/api/46/project/{project_name}/resources?format=json'
    headers = {}
    if token:
        headers['X-Rundeck-Auth-Token'] = token

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if not response.ok:
            cache.set(cache_key, [], timeout=20)
            return []
        resources = _normalize_rundeck_resources(response.json())
        cache.set(cache_key, resources, timeout=30)
        return resources
    except requests.RequestException:
        cache.set(cache_key, [], timeout=20)
        return []


class HostInventoryViewSet(viewsets.ViewSet):
    """Return paged host inventory enriched with Rundeck provider metadata."""

    def get_permissions(self):
        # Keep read behavior aligned with existing host endpoint usage in plugin.
        return [AllowAny()]

    def list(self, request):
        try:
            page = max(1, int(request.query_params.get('page', '1') or 1))
        except (ValueError, TypeError):
            return Response(
                {'status': 'error', 'message': 'page must be an integer'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            page_size = int(request.query_params.get('page_size', '50') or 50)
        except (ValueError, TypeError):
            return Response(
                {'status': 'error', 'message': 'page_size must be an integer'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        page_size = min(max(page_size, 1), 200)
        search = str(request.query_params.get('search', '') or '').strip().lower()
        ordering = str(request.query_params.get('ordering', 'hostname') or 'hostname')
        include_facets = str(request.query_params.get('include_facets', 'true') or 'true').strip().lower() in {
            '1', 'true', 'yes', 'on'
        }
        provider_filter = str(request.query_params.get('provider', '') or '').strip().lower()
        region_filter = str(request.query_params.get('region', '') or '').strip().lower()
        project_filter = str(request.query_params.get('project', '') or '').strip().lower()
        subscription_filter = str(request.query_params.get('subscription', '') or '').strip().lower()
        project_or_subscription_filter = str(
            request.query_params.get('project_or_subscription', '') or ''
        ).strip().lower()
        resource_group_filter = str(request.query_params.get('resource_group', '') or '').strip().lower()
        zone_filter = str(request.query_params.get('zone', '') or '').strip().lower()
        account_scope_filter = str(request.query_params.get('account_scope', '') or '').strip().lower()

        rundeck_host = str(request.query_params.get('rundeck_host', '') or '').strip()
        rundeck_project = str(request.query_params.get('rundeck_project', 'patchman') or 'patchman').strip()
        rundeck_token = request.headers.get('X-Rundeck-Auth-Token') or request.query_params.get('rundeck_token', '')

        hosts_qs = Host.objects.select_related(
            'osvariant', 'arch', 'domain',
        ).prefetch_related('tags').all()
        hosts = HostInventoryItemSerializer(hosts_qs, many=True, context={'request': request}).data

        resources = _get_rundeck_resources(rundeck_host, rundeck_project, rundeck_token)
        resource_indexes = _build_resource_indexes(resources)

        merged = []
        for host in hosts:
            hostname = host.get('hostname', '')
            host_name = _normalize_hostname(hostname)
            short_name = host_name.split('.', 1)[0] if host_name else ''
            host_ip = str(host.get('ipaddress') or '').strip().lower()
            matched = (
                (resource_indexes['by_ip'].get(host_ip) if host_ip else None)
                or resource_indexes['by_name'].get(host_name)
                or resource_indexes['by_short'].get(short_name)
            )

            provider = (matched or {}).get('inventory_provider') or (matched or {}).get('provider') or 'patchman'
            provider = _normalize_provider(provider)
            provider_vm_name = (
                (matched or {}).get('provider_vm_name')
                or (matched or {}).get('vm_name')
                or ((matched or {}).get('attributes') or {}).get('provider_vm_name')
                or ((matched or {}).get('attributes') or {}).get('vm_name')
                or ''
            )
            provider_instance_id = (
                (matched or {}).get('provider_instance_id')
                or ((matched or {}).get('attributes') or {}).get('provider_instance_id')
                or ''
            )

            project_or_subscription = _resource_value(
                matched,
                [
                    'project_or_subscription',
                    'project',
                    'project_id',
                    'gcp_project',
                    'subscription',
                    'subscription_id',
                    'azure_subscription_id',
                ],
            )
            resource_group_or_folder = _resource_value(
                matched,
                ['resource_group_or_folder', 'resource_group', 'resourcegroup', 'folder'],
            )
            account_scope = _resource_value(
                matched,
                ['account_scope', 'organization', 'org', 'tenant_id', 'tenant'],
            ) or project_or_subscription
            region = _resource_value(matched, ['region', 'location'])
            zone = _resource_value(matched, ['zone'])
            # Normalize GCP region/zone: fold zone into region for stable regional filtering.
            if provider == 'gcp':
                zone = _normalize_gcp_zone(zone)
                region = _normalize_gcp_location(region or zone)
            # Normalize Azure location/zone for stable filtering.
            if provider == 'azure':
                zone = _normalize_azure_zone(zone)
                region = _normalize_azure_location(region)

            enriched = dict(host)
            enriched['_provider'] = provider
            enriched['_providerVmName'] = provider_vm_name
            enriched['_providerInstanceId'] = provider_instance_id
            enriched['inventory_state'] = (matched or {}).get('inventory_state') or 'managed'
            # Canonical multi-cloud fields for cross-provider filtering and display.
            enriched['provider'] = provider
            enriched['resource_id'] = provider_instance_id
            enriched['instance_name'] = provider_vm_name or hostname
            enriched['project_or_subscription'] = project_or_subscription
            enriched['resource_group_or_folder'] = resource_group_or_folder
            enriched['account_scope'] = account_scope
            enriched['region'] = region
            enriched['zone'] = zone
            merged.append(enriched)

        if provider_filter:
            merged = [
                item for item in merged
                if str(item.get('provider') or '').strip().lower() == provider_filter
            ]
        if region_filter:
            merged = [
                item for item in merged
                if str(item.get('region') or '').strip().lower() == region_filter
            ]

        project_scope_filter = project_or_subscription_filter or project_filter or subscription_filter
        if project_scope_filter:
            merged = [
                item for item in merged
                if str(item.get('project_or_subscription') or '').strip().lower() == project_scope_filter
            ]
        if resource_group_filter:
            merged = [
                item for item in merged
                if str(item.get('resource_group_or_folder') or '').strip().lower() == resource_group_filter
            ]
        if zone_filter:
            merged = [
                item for item in merged
                if str(item.get('zone') or '').strip().lower() == zone_filter
            ]
        if account_scope_filter:
            merged = [
                item for item in merged
                if str(item.get('account_scope') or '').strip().lower() == account_scope_filter
            ]

        if search:
            def _match(item):
                haystack = ' '.join([
                    str(item.get('hostname') or ''),
                    str(item.get('ipaddress') or ''),
                    str(item.get('reversedns') or ''),
                    str(item.get('_provider') or ''),
                    str(item.get('_providerVmName') or ''),
                    str(item.get('_providerInstanceId') or ''),
                    str(item.get('project_or_subscription') or ''),
                    str(item.get('resource_group_or_folder') or ''),
                    str(item.get('account_scope') or ''),
                    str(item.get('region') or ''),
                    str(item.get('zone') or ''),
                    ' '.join(item.get('tags') or []),
                ]).lower()
                return search in haystack

            merged = [item for item in merged if _match(item)]

        descending = ordering.startswith('-')
        sort_field = ordering[1:] if descending else ordering
        field_map = {
            'hostname': 'hostname',
            'ipaddress': 'ipaddress',
            'lastreport': 'lastreport',
            'updated_at': 'updated_at',
            'bugfix_update_count': 'bugfix_update_count',
            'security_update_count': 'security_update_count',
            'local_bugfix_update_count': 'local_bugfix_update_count',
            'local_security_update_count': 'local_security_update_count',
            'local_phased_deferred_count': 'local_phased_deferred_count',
            'calculated_bugfix_update_count': 'calculated_bugfix_update_count',
            'calculated_security_update_count': 'calculated_security_update_count',
            'reboot_required': 'reboot_required',
            'provider': '_provider',
            'provider_vm_name': '_providerVmName',
            'provider_instance_id': '_providerInstanceId',
            'project_or_subscription': 'project_or_subscription',
            'resource_group_or_folder': 'resource_group_or_folder',
            'account_scope': 'account_scope',
            'region': 'region',
            'zone': 'zone',
        }
        key_name = field_map.get(sort_field, 'hostname')
        merged.sort(key=lambda item: str(item.get(key_name) or '').lower(), reverse=descending)

        facets = None
        if include_facets:
            def _facet_counts(field_name):
                counts = {}
                for item in merged:
                    value = str(item.get(field_name) or '').strip()
                    if not value:
                        continue
                    counts[value] = counts.get(value, 0) + 1

                values = list(counts.keys())
                values.sort(key=lambda val: (-counts[val], val.lower()))
                return [
                    {'value': value, 'count': counts[value]}
                    for value in values
                ]

            facets = {
                'provider': _facet_counts('provider'),
                'region': _facet_counts('region'),
                'project_or_subscription': _facet_counts('project_or_subscription'),
                'resource_group_or_folder': _facet_counts('resource_group_or_folder'),
                'zone': _facet_counts('zone'),
            }

        total = len(merged)
        start = (page - 1) * page_size
        end = start + page_size
        results = merged[start:end]

        def build_page_url(page_number):
            if page_number < 1:
                return None
            if page_number > 1 and (page_number - 1) * page_size >= total:
                return None

            split = urlsplit(request.build_absolute_uri())
            query = dict(request.query_params)
            query['page'] = str(page_number)
            query['page_size'] = str(page_size)
            return urlunsplit((split.scheme, split.netloc, split.path, urlencode(query, doseq=True), split.fragment))

        next_url = build_page_url(page + 1)
        previous_url = build_page_url(page - 1) if page > 1 else None

        payload = {
            'count': total,
            'next': next_url,
            'previous': previous_url,
            'results': results,
        }
        if facets is not None:
            payload['facets'] = facets

        return Response(payload, status=status.HTTP_200_OK)


class CeleryMetricsViewSet(viewsets.ViewSet):
    """Return basic Celery runtime metrics for UI status display."""

    def get_permissions(self):
        return [HasAPIKeyOrIsAuthenticatedOrReadOnly()]

    def list(self, request):
        workers_count = None
        jobs_in_progress = None
        jobs_in_queue = None

        # Worker and active-task metrics from Celery inspect.
        try:
            inspector = celery_app.control.inspect(timeout=1)
            stats = inspector.stats() or {}
            active = inspector.active() or {}
            workers_count = len(stats.keys()) if isinstance(stats, dict) else 0
            if isinstance(active, dict):
                jobs_in_progress = sum(len(tasks or []) for tasks in active.values())
            else:
                jobs_in_progress = 0
        except Exception:
            pass

        # Queue depth from Redis broker list length (default queue).
        try:
            broker_url = str(getattr(settings, 'CELERY_BROKER_URL', '') or '').strip()
            parsed = urlparse(broker_url)
            if parsed.scheme.startswith('redis'):
                queue_name = getattr(settings, 'CELERY_TASK_DEFAULT_QUEUE', 'celery')
                redis_client = redis.Redis.from_url(broker_url)
                jobs_in_queue = int(redis_client.llen(queue_name))
        except Exception:
            pass

        return Response(
            {
                'workers_count': workers_count,
                'jobs_in_queue': jobs_in_queue,
                'jobs_in_progress': jobs_in_progress,
            },
            status=status.HTTP_200_OK,
        )


@method_decorator(never_cache, name='dispatch')
class HostInventoryHostgroupViewSet(viewsets.ViewSet):
    """Persist host inventory hostgroups shared across all users."""

    def get_permissions(self):
        # Reads (list/retrieve) are open; writes require API key or session auth.
        if self.action in ('list', 'retrieve'):
            return [AllowAny()]
        return [HasAPIKeyOrIsAuthenticatedOrReadOnly()]

    def list(self, request):
        hostgroups = HostInventoryHostgroup.objects.all()
        serializer = HostInventoryHostgroupSerializer(hostgroups, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def create(self, request):
        serializer = HostInventoryHostgroupMutationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        hostgroup = HostInventoryHostgroup.objects.create(
            name=serializer.validated_data['name'],
            state=serializer.validated_data['state'],
        )
        response_serializer = HostInventoryHostgroupSerializer(hostgroup)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)

    def retrieve(self, request, pk=None):
        hostgroup = get_object_or_404(HostInventoryHostgroup, pk=pk)
        serializer = HostInventoryHostgroupSerializer(hostgroup)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def update(self, request, pk=None):
        hostgroup = get_object_or_404(HostInventoryHostgroup, pk=pk)
        serializer = HostInventoryHostgroupMutationSerializer(data=request.data, partial=False)
        serializer.is_valid(raise_exception=True)
        hostgroup.name = serializer.validated_data['name']
        hostgroup.state = serializer.validated_data['state']
        hostgroup.save(update_fields=['name', 'state', 'updated_at'])
        response_serializer = HostInventoryHostgroupSerializer(hostgroup)
        return Response(response_serializer.data, status=status.HTTP_200_OK)

    def partial_update(self, request, pk=None):
        hostgroup = get_object_or_404(HostInventoryHostgroup, pk=pk)
        serializer = HostInventoryHostgroupMutationSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)

        if 'name' in serializer.validated_data:
            hostgroup.name = serializer.validated_data['name'] or hostgroup.name
        if 'state' in serializer.validated_data:
            hostgroup.state = serializer.validated_data['state']
        hostgroup.save(update_fields=['name', 'state', 'updated_at'])
        response_serializer = HostInventoryHostgroupSerializer(hostgroup)
        return Response(response_serializer.data, status=status.HTTP_200_OK)

    def destroy(self, request, pk=None):
        hostgroup = get_object_or_404(HostInventoryHostgroup, pk=pk)
        hostgroup.delete()
        return Response({'status': 'deleted'}, status=status.HTTP_200_OK)


class OperationsThrottle(AnonRateThrottle):
    """Rate-limit the unauthenticated operations endpoint to prevent queue flooding.

    Default: 60 requests / hour per IP.  Override with
    ``OPERATIONS_THROTTLE_RATE`` in local_settings.py (e.g. ``'120/hour'``).
    """

    @property
    def rate(self):
        return getattr(settings, 'OPERATIONS_THROTTLE_RATE', '60/hour')


class OperationViewSet(viewsets.ViewSet):
    """Queue asynchronous Patchman operations via Celery tasks."""

    throttle_classes = [OperationsThrottle]

    def get_permissions(self):
        # Operations endpoint is intentionally unauthenticated.
        return [AllowAny()]

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
            repo_id = params.get('repo_id')
            if repo_id is not None:
                get_object_or_404(Repository, id=repo_id)
            result = update_errata_task.delay(
                erratum_type=params.get('erratum_type'),
                force=params.get('force', False),
                repo=repo_id,
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
            # Get all unprocessed reports for this host. Do not require a
            # Host row to exist yet, because hosts are created during
            # Report.process().
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
