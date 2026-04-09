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

import json

from rest_framework import serializers

from util.models import HostInventoryHostgroup


class OperationRequestSerializer(serializers.Serializer):
    OPERATION_CHOICES = [
        'refresh_repos',
        'host_updates',
        'host_updates_alt',
        'process_reports',
        'dbcheck',
        'update_errata',
        'update_cves',
    ]
    ERRATUM_TYPES = {'yum', 'rocky', 'alma', 'arch', 'ubuntu', 'debian', 'centos'}

    operation = serializers.ChoiceField(choices=OPERATION_CHOICES)
    params = serializers.DictField(required=False, default=dict)

    def validate(self, attrs):
        operation = attrs['operation']
        params = attrs.get('params') or {}

        if not isinstance(params, dict):
            raise serializers.ValidationError({'params': 'Must be an object.'})

        validators = {
            'refresh_repos': self._validate_refresh_repos,
            'host_updates': self._validate_host_updates,
            'host_updates_alt': lambda p: self._validate_no_params(p, 'host_updates_alt'),
            'process_reports': self._validate_process_reports,
            'dbcheck': self._validate_dbcheck,
            'update_errata': self._validate_update_errata,
            'update_cves': self._validate_update_cves,
        }
        validators[operation](params)

        attrs['params'] = params
        return attrs

    def _validate_allowed(self, params, allowed, operation):
        unknown = set(params.keys()) - allowed
        if unknown:
            key_list = ', '.join(sorted(unknown))
            raise serializers.ValidationError(
                {'params': f'Unsupported parameter(s) for {operation}: {key_list}'}
            )

    def _validate_no_params(self, params, operation):
        self._validate_allowed(params, set(), operation)

    def _validate_refresh_repos(self, params):
        self._validate_allowed(params, {'repo_id', 'force'}, 'refresh_repos')

        if 'repo_id' in params and not isinstance(params['repo_id'], int):
            raise serializers.ValidationError({'params': 'repo_id must be an integer'})
        if 'force' in params and not isinstance(params['force'], bool):
            raise serializers.ValidationError({'params': 'force must be a boolean'})

    def _validate_host_updates(self, params):
        self._validate_allowed(params, {'host'}, 'host_updates')

        if 'host' in params and not isinstance(params['host'], str):
            raise serializers.ValidationError({'params': 'host must be a string'})

    def _validate_process_reports(self, params):
        self._validate_allowed(params, {'host'}, 'process_reports')

        if 'host' in params and not isinstance(params['host'], str):
            raise serializers.ValidationError({'params': 'host must be a string'})

    def _validate_dbcheck(self, params):
        self._validate_allowed(params, {'remove_duplicates'}, 'dbcheck')

        if 'remove_duplicates' in params and not isinstance(params['remove_duplicates'], bool):
            raise serializers.ValidationError({'params': 'remove_duplicates must be a boolean'})

    def _validate_update_errata(self, params):
        self._validate_allowed(params, {'erratum_type', 'force', 'repo_id'}, 'update_errata')

        if 'force' in params and not isinstance(params['force'], bool):
            raise serializers.ValidationError({'params': 'force must be a boolean'})
        if 'repo_id' in params and not isinstance(params['repo_id'], int):
            raise serializers.ValidationError({'params': 'repo_id must be an integer'})

        if 'erratum_type' in params:
            erratum_type = params['erratum_type']
            if not isinstance(erratum_type, str):
                raise serializers.ValidationError({'params': 'erratum_type must be a string'})
            if erratum_type not in self.ERRATUM_TYPES:
                allowed = ', '.join(sorted(self.ERRATUM_TYPES))
                raise serializers.ValidationError(
                    {'params': f'erratum_type must be one of: {allowed}'}
                )

    def _validate_update_cves(self, params):
        self._validate_allowed(params, {'cve_id'}, 'update_cves')

        if 'cve_id' in params and not isinstance(params['cve_id'], str):
            raise serializers.ValidationError({'params': 'cve_id must be a string'})


class HostInventoryHostgroupMutationSerializer(serializers.Serializer):
    name = serializers.CharField(required=False, allow_blank=True, max_length=255)
    state = serializers.JSONField(required=False)

    def validate_state(self, value):
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError as exc:
                raise serializers.ValidationError('Must be valid JSON.') from exc

        if not isinstance(value, dict):
            raise serializers.ValidationError('Must be an object.')

        cloud_filters = value.get('cloudFilters') or {}
        if cloud_filters and not isinstance(cloud_filters, dict):
            raise serializers.ValidationError({'cloudFilters': 'Must be an object.'})

        normalized = {
            'searchTerm': str(value.get('searchTerm') or '').strip(),
            'sortField': str(value.get('sortField') or 'hostname').strip() or 'hostname',
            'sortDir': -1 if value.get('sortDir') == -1 else 1,
            'topTab': 'add-hosts' if value.get('topTab') == 'add-hosts' else 'host-management',
            'cloudFilters': {
                'provider': str(cloud_filters.get('provider') or '').strip(),
                'region': str(cloud_filters.get('region') or '').strip(),
                'projectOrSubscription': str(cloud_filters.get('projectOrSubscription') or '').strip(),
                'resourceGroup': str(cloud_filters.get('resourceGroup') or '').strip(),
            },
        }
        return normalized

    def validate(self, attrs):
        if 'state' not in attrs and not self.partial:
            raise serializers.ValidationError({'state': 'This field is required.'})
        if 'name' in attrs:
            name = str(attrs['name'] or '').strip()
            attrs['name'] = name or 'Hostgroup'
        return attrs


class HostInventoryHostgroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = HostInventoryHostgroup
        fields = (
            'id',
            'name',
            'state',
            'created_at',
            'updated_at',
        )
