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
    SECRET_KEY='test-secret-key',
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
                'region': 'homelab-east',
                'project': 'core-lab',
                'resource_group': 'infra',
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
        self.assertEqual(response.data['results'][0]['provider'], 'proxmox')
        self.assertEqual(response.data['results'][0]['region'], 'homelab-east')
        self.assertEqual(response.data['results'][0]['project_or_subscription'], 'core-lab')
        self.assertEqual(response.data['results'][0]['resource_group_or_folder'], 'infra')

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

    @patch('util.api_views.requests.get')
    def test_filters_by_provider_region_and_project_scope(self, mock_get):
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = [
            {
                'nodename': 'vm01.example.com',
                'hostname': '10.0.0.11',
                'inventory_provider': 'gcp',
                'provider_vm_name': 'gce-vm-01',
                'provider_instance_id': 'gcp-1',
                'project': 'proj-a',
                'region': 'us-central1',
                'resource_group': '',
                'inventory_state': 'managed',
            }
        ]
        mock_get.return_value = mock_response

        response = self.client.get(
            self.url,
            {
                'rundeck_host': 'http://rundeck.local',
                'rundeck_project': 'patchman',
                'provider': 'gcp',
                'region': 'us-central1',
                'project_or_subscription': 'proj-a',
            },
            HTTP_X_RUNDECK_AUTH_TOKEN='token123',
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)
        item = response.data['results'][0]
        self.assertEqual(item['provider'], 'gcp')
        self.assertEqual(item['region'], 'us-central1')
        self.assertEqual(item['project_or_subscription'], 'proj-a')

    @patch('util.api_views.requests.get')
    def test_filters_by_resource_group_and_account_scope(self, mock_get):
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = [
            {
                'nodename': 'vm01.example.com',
                'hostname': '10.0.0.11',
                'inventory_provider': 'azure',
                'provider_vm_name': 'az-vm-01',
                'provider_instance_id': 'az-1',
                'subscription_id': 'sub-prod',
                'resource_group': 'rg-prod',
                'tenant_id': 'tenant-main',
                'region': 'canadacentral',
                'inventory_state': 'managed',
            }
        ]
        mock_get.return_value = mock_response

        response = self.client.get(
            self.url,
            {
                'rundeck_host': 'http://rundeck.local',
                'rundeck_project': 'patchman',
                'resource_group': 'rg-prod',
                'account_scope': 'tenant-main',
            },
            HTTP_X_RUNDECK_AUTH_TOKEN='token123',
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)
        item = response.data['results'][0]
        self.assertEqual(item['project_or_subscription'], 'sub-prod')
        self.assertEqual(item['resource_group_or_folder'], 'rg-prod')
        self.assertEqual(item['account_scope'], 'tenant-main')

    @patch('util.api_views.requests.get')
    def test_response_includes_cloud_facets(self, mock_get):
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = [
            {
                'nodename': 'vm01.example.com',
                'hostname': '10.0.0.11',
                'inventory_provider': 'gcp',
                'provider_vm_name': 'gce-vm-01',
                'provider_instance_id': 'gcp-1',
                'project': 'proj-a',
                'region': 'us-central1',
                'resource_group': 'folder-a',
                'inventory_state': 'managed',
            }
        ]
        mock_get.return_value = mock_response

        response = self.client.get(
            self.url,
            {
                'rundeck_host': 'http://rundeck.local',
                'rundeck_project': 'patchman',
            },
            HTTP_X_RUNDECK_AUTH_TOKEN='token123',
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('facets', response.data)
        facets = response.data['facets']
        self.assertIn('provider', facets)
        self.assertIn('region', facets)
        self.assertIn('project_or_subscription', facets)
        self.assertIn('resource_group_or_folder', facets)
        self.assertEqual(facets['provider'][0]['value'], 'gcp')

    @patch('util.api_views.requests.get')
    def test_include_facets_false_omits_facets(self, mock_get):
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = [
            {
                'nodename': 'vm01.example.com',
                'hostname': '10.0.0.11',
                'inventory_provider': 'proxmox',
                'provider_vm_name': 'vm-one',
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
                'include_facets': 'false',
            },
            HTTP_X_RUNDECK_AUTH_TOKEN='token123',
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotIn('facets', response.data)

    @patch('util.api_views.requests.get')
    def test_gcp_provider_alias_normalization(self, mock_get):
        """Test that GCP provider name aliases are normalized to 'gcp'."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = [
            {
                'nodename': 'vm01.example.com',  # Match the test host
                'hostname': '10.0.0.11',  # Match the test host IP
                'inventory_provider': 'gce',  # GCP alias: gce -> should normalize to gcp
                'provider_vm_name': 'gce-instance',
                'provider_instance_id': 'gce-1',
                'project': 'my-project',
                'region': 'us-central1',
                'inventory_state': 'managed',
            }
        ]
        mock_get.return_value = mock_response

        response = self.client.get(
            self.url,
            {
                'rundeck_host': 'http://rundeck.local',
                'rundeck_project': 'patchman',
                'provider': 'gcp',  # Filter by normalized name
            },
            HTTP_X_RUNDECK_AUTH_TOKEN='token123',
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Verify instance is returned when filtering by 'gcp' even though source was 'gce'
        self.assertEqual(response.data['count'], 1)
        item = response.data['results'][0]
        self.assertEqual(item['provider'], 'gcp')

    @patch('util.api_views.requests.get')
    def test_gcp_zone_to_region_derivation(self, mock_get):
        """Test that GCP zone is normalized and region is derived from zone if missing."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = [
            {
                'nodename': 'vm01.example.com',  # Match the test host
                'hostname': '10.0.0.11',  # Match the test host IP
                'inventory_provider': 'gcp',
                'provider_vm_name': 'zoned-instance',
                'provider_instance_id': 'gce-2',
                'project': 'my-project',
                'zone': 'us-central1-a',  # Only zone provided, no region
                'inventory_state': 'managed',
            }
        ]
        mock_get.return_value = mock_response

        response = self.client.get(
            self.url,
            {
                'rundeck_host': 'http://rundeck.local',
                'rundeck_project': 'patchman',
                'region': 'us-central1',  # Filter by derived region from zone
            },
            HTTP_X_RUNDECK_AUTH_TOKEN='token123',
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Verify instance is returned when filtering by region derived from zone
        self.assertEqual(response.data['count'], 1)
        item = response.data['results'][0]
        self.assertEqual(item['zone'], 'us-central1-a')
        self.assertEqual(item['region'], 'us-central1')  # Derived from zone

    @patch('util.api_views.requests.get')
    def test_azure_provider_alias_normalization(self, mock_get):
        """Test that Azure provider name aliases are normalized to 'azure'."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = [
            {
                'nodename': 'vm01.example.com',  # Match the test host
                'hostname': '10.0.0.11',  # Match the test host IP
                'inventory_provider': 'ms-azure',  # Azure alias: ms-azure -> should normalize to azure
                'provider_vm_name': 'azure-vm',
                'provider_instance_id': 'azure-1',
                'subscription': 'my-subscription',
                'location': 'eastus',
                'resource_group': 'rg-prod',
                'inventory_state': 'managed',
            }
        ]
        mock_get.return_value = mock_response

        response = self.client.get(
            self.url,
            {
                'rundeck_host': 'http://rundeck.local',
                'rundeck_project': 'patchman',
                'provider': 'azure',  # Filter by normalized name
            },
            HTTP_X_RUNDECK_AUTH_TOKEN='token123',
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Verify instance is returned when filtering by 'azure' even though source was 'ms-azure'
        self.assertEqual(response.data['count'], 1)
        item = response.data['results'][0]
        self.assertEqual(item['provider'], 'azure')
        self.assertEqual(item['region'], 'eastus')

    @patch('util.api_views.requests.get')
    def test_azure_location_normalization(self, mock_get):
        """Test that Azure location is normalized and region filtering works."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = [
            {
                'nodename': 'vm01.example.com',  # Match the test host
                'hostname': '10.0.0.11',  # Match the test host IP
                'inventory_provider': 'azure',
                'provider_vm_name': 'location-instance',
                'provider_instance_id': 'azure-2',
                'subscription': 'my-subscription',
                'location': 'westus2',  # Azure location
                'zone': '2',  # Availability zone
                'resource_group': 'rg-prod',
                'inventory_state': 'managed',
            }
        ]
        mock_get.return_value = mock_response

        response = self.client.get(
            self.url,
            {
                'rundeck_host': 'http://rundeck.local',
                'rundeck_project': 'patchman',
                'region': 'westus2',  # Filter by normalized location
            },
            HTTP_X_RUNDECK_AUTH_TOKEN='token123',
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Verify instance is returned when filtering by region/location
        self.assertEqual(response.data['count'], 1)
        item = response.data['results'][0]
        self.assertEqual(item['region'], 'westus2')
        self.assertEqual(item['zone'], '2')
