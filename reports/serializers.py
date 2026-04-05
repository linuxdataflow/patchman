# Copyright 2013-2025 Marcus Furlong <furlongm@gmail.com>
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


class PackageSerializer(serializers.Serializer):
    """Serializer for a single package in a report."""
    name = serializers.CharField(max_length=255)
    epoch = serializers.CharField(max_length=255, required=False, allow_blank=True, default='')
    version = serializers.CharField(max_length=255)
    release = serializers.CharField(max_length=255, required=False, allow_blank=True, default='')
    arch = serializers.CharField(max_length=255)
    type = serializers.ChoiceField(choices=['deb', 'rpm', 'arch', 'gentoo'])
    # Gentoo-specific fields
    category = serializers.CharField(max_length=255, required=False, allow_blank=True, default='')
    repo = serializers.CharField(max_length=255, required=False, allow_blank=True, default='')


class RepoSerializer(serializers.Serializer):
    """Serializer for a single repository in a report."""
    type = serializers.ChoiceField(choices=['deb', 'rpm', 'arch', 'gentoo'])
    name = serializers.CharField(max_length=255)
    id = serializers.CharField(max_length=255, required=False, allow_blank=True, default='')
    priority = serializers.IntegerField(required=False, default=0)
    urls = serializers.ListField(
        child=serializers.URLField(max_length=512),
        required=False,
        default=list
    )


class ModuleSerializer(serializers.Serializer):
    """Serializer for a single module in a report."""
    name = serializers.CharField(max_length=255)
    stream = serializers.CharField(max_length=255)
    version = serializers.CharField(max_length=255)
    context = serializers.CharField(max_length=255)
    arch = serializers.CharField(max_length=255)
    repo = serializers.CharField(max_length=255, required=False, allow_blank=True, default='')
    packages = serializers.ListField(
        child=serializers.CharField(max_length=255),
        required=False,
        default=list
    )


class UpdateSerializer(serializers.Serializer):
    """Serializer for a single update (security or bugfix) in a report."""
    name = serializers.CharField(max_length=255)
    version = serializers.CharField(max_length=255)
    arch = serializers.CharField(max_length=255)
    repo = serializers.CharField(max_length=255, required=False, allow_blank=True, default='')


class ReportUploadSerializer(serializers.Serializer):
    """Serializer for protocol 2 JSON report uploads."""
    protocol = serializers.IntegerField(default=2)
    hostname = serializers.CharField(max_length=255)
    arch = serializers.CharField(max_length=255)
    kernel = serializers.CharField(max_length=255)
    os = serializers.CharField(max_length=255)
    tags = serializers.ListField(
        child=serializers.CharField(max_length=255),
        required=False,
        default=list
    )
    reboot_required = serializers.BooleanField(required=False, default=False)
    packages = PackageSerializer(many=True, required=False, default=list)
    repos = RepoSerializer(many=True, required=False, default=list)
    modules = ModuleSerializer(many=True, required=False, default=list)
    sec_updates = UpdateSerializer(many=True, required=False, default=list)
    bug_updates = UpdateSerializer(many=True, required=False, default=list)
    installed_packages = UpdateSerializer(many=True, required=False, default=list)
    phased_deferred_updates = UpdateSerializer(many=True, required=False, default=list)

    def validate_protocol(self, value):
        if value != 2:
            raise serializers.ValidationError('This endpoint only accepts protocol 2')
        return value


class ReportSerializer(serializers.HyperlinkedModelSerializer):
    """Serializer for reading Report model instances."""

    installed_packages_count = serializers.SerializerMethodField()

    def get_installed_packages_count(self, obj):
        if obj.protocol == '2':
            return len(obj.installed_packages_parsed)
        if not obj.installed_packages:
            return 0
        return len([line for line in obj.installed_packages.splitlines() if line.strip()])

    class Meta:
        from reports.models import Report
        model = Report
        fields = (
            'id', 'host', 'domain', 'tags', 'kernel', 'arch', 'os',
            'report_ip', 'protocol', 'useragent', 'processed', 'created',
            'installed_packages_count'
        )


class ReportDetailSerializer(ReportSerializer):
    """Serializer for report detail responses with full installed package list."""

    installed_packages = serializers.SerializerMethodField()

    def get_installed_packages(self, obj):
        if obj.protocol == '2':
            return obj.installed_packages_parsed

        parsed = []
        if not obj.installed_packages:
            return parsed

        for line in obj.installed_packages.splitlines():
            row = line.strip()
            if not row:
                continue

            parts = row.split()
            if len(parts) < 2:
                continue

            name_arch = parts[0]
            version = parts[1]
            repo = parts[2] if len(parts) > 2 else ''

            if '.' in name_arch:
                name, arch = name_arch.rsplit('.', 1)
            else:
                name = name_arch
                arch = ''

            parsed.append({
                'name': name,
                'version': version,
                'arch': arch,
                'repo': repo,
            })

        return parsed

    class Meta(ReportSerializer.Meta):
        fields = ReportSerializer.Meta.fields + ('installed_packages',)
