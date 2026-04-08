# Copyright 2016-2021 Marcus Furlong <furlongm@gmail.com>
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

from rest_framework import serializers
from taggit.serializers import TagListSerializerField

from hosts.models import Host, HostRepo


class HostSerializer(serializers.HyperlinkedModelSerializer):
    bugfix_update_count = serializers.SerializerMethodField()
    security_update_count = serializers.SerializerMethodField()
    local_bugfix_update_count = serializers.SerializerMethodField()
    local_security_update_count = serializers.SerializerMethodField()
    local_phased_deferred_count = serializers.SerializerMethodField()
    calculated_bugfix_update_count = serializers.SerializerMethodField()
    calculated_security_update_count = serializers.SerializerMethodField()
    tags = TagListSerializerField()

    class Meta:
        model = Host
        fields = ('id', 'hostname', 'ipaddress', 'reversedns', 'check_dns',
                  'osvariant', 'kernel', 'arch', 'domain', 'lastreport', 'repos',
                  'updates', 'reboot_required', 'host_repos_only', 'tags',
                  'updated_at', 'bugfix_update_count', 'security_update_count',
                  'local_bugfix_update_count', 'local_security_update_count',
                  'local_phased_deferred_count',
                  'calculated_bugfix_update_count', 'calculated_security_update_count',
                  'provider_name', 'provider_instance_id', 'provider_vm_name',
                  'provider_region', 'provider_zone', 'provider_account_scope',
                  'provider_resource_group', 'provider_machine_id',
                  'last_provider_power_state', 'last_provider_sync_at',
                  'reconcile_confidence', 'reconcile_reason')

    def get_bugfix_update_count(self, obj):
        return obj.calc_bug_updates_count

    def get_security_update_count(self, obj):
        return obj.calc_sec_updates_count

    def get_local_bugfix_update_count(self, obj):
        return obj.local_bug_updates_count

    def get_local_security_update_count(self, obj):
        return obj.local_sec_updates_count

    def get_local_phased_deferred_count(self, obj):
        return obj.local_phased_deferred_count

    def get_calculated_bugfix_update_count(self, obj):
        return obj.calc_bug_updates_count

    def get_calculated_security_update_count(self, obj):
        return obj.calc_sec_updates_count


class HostRepoSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = HostRepo
        fields = ('host', 'repo', 'enabled', 'priority')
