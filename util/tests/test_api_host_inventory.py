from unittest.mock import Mock, patch

from django.core.cache import cache
from django.test import override_settings
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase

from arch.models import MachineArchitecture
from domains.models import Domain
from hosts.models import Host
from operatingsystems.models import OSRelease, OSVariant


@override_settings(
    REQUIRE_API_KEY=False,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
)
class HostInventoryAPITests(APITestCase):
    def setUp(self):
        self.url = '/api/host-inventory/'
        cache.clear()

        self.arch = MachineArchitecture.objects.create(name='x86_64')
        self.domain = Domain.objects.create(name='example.com')
        self.os_release = OSRelease.objects.create(name='Ubuntu 24.04', codename='noble')
        self.os_variant = OSVariant.objects.create(name='Ubuntu 24.04 LTS', osrelease=self.os_release)

        self.host = Host.objects.create(
            hostname='vm01.example.com',
            ipaddress='10.0.0.11',
            osvariant=self.os_variant,
            kernel='6.8.0-31-generic',
            arch=self.arch,
            domain=self.domain,
            lastreport=timezone.now(),
        )

    @patch('util.api_views.requests.get')
    def test_list_returns_enriched_results(self, mock_get):
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = [
            {
                'nodename': 'vm01.example.com',
                'hostname': '10.0.0.11',
                'inventory_provider': 'proxmox',
                'provider_vm_name': 'lab-vm-01',
                'provider_instance_id': '1001',
                'inventory_state': 'managed',
            }
        ]
        mock_get.return_value = mock_response

        response = self.client.get(
            self.url,
            {
                'rundeck_host': 'http://rundeck.local',
                'rundeck_project': 'patchman',
                'page_size': 10,
            },
            HTTP_X_RUNDECK_AUTH_TOKEN='token123',
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['results'][0]['hostname'], 'vm01.example.com')
        self.assertEqual(response.data['results'][0]['_provider'], 'proxmox')
        self.assertEqual(response.data['results'][0]['_providerVmName'], 'lab-vm-01')

    @patch('util.api_views.requests.get')
    def test_search_by_provider_vm_name(self, mock_get):
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = [
            {
                'nodename': 'vm01.example.com',
                'hostname': '10.0.0.11',
                'inventory_provider': 'proxmox',
                'provider_vm_name': 'corp-db-primary',
                'provider_instance_id': '1001',
                'inventory_state': 'managed',
            }
        ]
        mock_get.return_value = mock_response

        response = self.client.get(
            self.url,
            {
                'rundeck_host': 'http://rundeck.local',
                'rundeck_project': 'patchman',
                'search': 'corp-db',
            },
            HTTP_X_RUNDECK_AUTH_TOKEN='token123',
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['results'][0]['_providerVmName'], 'corp-db-primary')

    @patch('util.api_views.requests.get')
    def test_rundeck_resources_are_cached(self, mock_get):
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = [
            {
                'nodename': 'vm01.example.com',
                'hostname': '10.0.0.11',
                'inventory_provider': 'proxmox',
                'provider_vm_name': 'cache-test-vm',
                'inventory_state': 'managed',
            }
        ]
        mock_get.return_value = mock_response

        query = {
            'rundeck_host': 'http://rundeck.local',
            'rundeck_project': 'patchman',
        }

        first = self.client.get(self.url, query, HTTP_X_RUNDECK_AUTH_TOKEN='token123')
        second = self.client.get(self.url, query, HTTP_X_RUNDECK_AUTH_TOKEN='token123')

        self.assertEqual(first.status_code, status.HTTP_200_OK)
        self.assertEqual(second.status_code, status.HTTP_200_OK)
        self.assertEqual(mock_get.call_count, 1)
