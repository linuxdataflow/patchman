from django.contrib.auth.models import User
from django.test import override_settings
from rest_framework import status
from rest_framework.test import APITestCase

from util.models import HostInventoryHostgroup


@override_settings(
    REQUIRE_API_KEY=False,
    SECRET_KEY='test-secret-key',
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
)
class HostInventoryHostgroupApiTests(APITestCase):
    def setUp(self):
        self.url = '/api/hostgroup/'
        self.user = User.objects.create_user(username='hguser', password='hgpass')
        self.client.force_authenticate(user=self.user)

    def test_create_hostgroup(self):
        response = self.client.post(
            self.url,
            {
                'name': 'Prod AWS',
                'state': {
                    'searchTerm': 'prod',
                    'sortField': 'hostname',
                    'sortDir': 1,
                    'topTab': 'host-management',
                    'cloudFilters': {'provider': 'aws'},
                },
            },
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['name'], 'Prod AWS')
        self.assertIn('id', response.data)
        self.assertEqual(HostInventoryHostgroup.objects.count(), 1)

    def test_retrieve_hostgroup(self):
        hostgroup = HostInventoryHostgroup.objects.create(
            name='GCP Group',
            state={'searchTerm': 'gcp', 'cloudFilters': {'provider': 'gcp'}},
        )

        response = self.client.get(f'{self.url}{hostgroup.id}/')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], 'GCP Group')
        self.assertEqual(response.data['state']['cloudFilters']['provider'], 'gcp')

    def test_patch_updates_hostgroup(self):
        hostgroup = HostInventoryHostgroup.objects.create(
            name='Baseline',
            state={'searchTerm': 'old'},
        )

        response = self.client.patch(
            f'{self.url}{hostgroup.id}/',
            {'name': 'Updated name', 'state': {'searchTerm': 'new'}},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        hostgroup.refresh_from_db()
        self.assertEqual(hostgroup.name, 'Updated name')
        self.assertEqual(hostgroup.state['searchTerm'], 'new')

    def test_delete_hostgroup(self):
        hostgroup = HostInventoryHostgroup.objects.create(
            name='Delete me',
            state={'searchTerm': 'delete'},
        )

        response = self.client.delete(f'{self.url}{hostgroup.id}/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(HostInventoryHostgroup.objects.filter(id=hostgroup.id).exists())

    def test_unauthenticated_write_is_rejected(self):
        self.client.force_authenticate(user=None)
        response = self.client.post(
            self.url,
            {'name': 'Open', 'state': {'searchTerm': 'open'}},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_unauthenticated_read_is_allowed(self):
        self.client.force_authenticate(user=None)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


@override_settings(
    REQUIRE_API_KEY=True,
    SECRET_KEY='test-secret-key',
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
)
class HostInventoryHostgroupApiAuthBypassTests(APITestCase):
    def test_unauthenticated_create_is_rejected_when_api_key_required(self):
        response = self.client.post(
            '/api/hostgroup/',
            {'name': 'Open', 'state': {'searchTerm': 'open'}},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
