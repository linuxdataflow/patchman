from django.test import override_settings
from rest_framework import status
from rest_framework.test import APITestCase

from util.models import HostInventorySharedView


@override_settings(
    REQUIRE_API_KEY=False,
    SECRET_KEY='test-secret-key',
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
)
class HostInventorySharedViewApiTests(APITestCase):
    def setUp(self):
        self.url = '/api/host-inventory-view/'

    def test_create_returns_share_and_manage_tokens(self):
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
        self.assertIn('share_token', response.data)
        self.assertIn('manage_token', response.data)
        self.assertEqual(HostInventorySharedView.objects.count(), 1)

    def test_retrieve_exposes_shared_state_without_manage_token(self):
        shared_view = HostInventorySharedView.objects.create(
            name='Shared GCP',
            state={'searchTerm': 'gcp', 'cloudFilters': {'provider': 'gcp'}},
        )

        response = self.client.get(f'{self.url}{shared_view.share_token}/')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], 'Shared GCP')
        self.assertNotIn('manage_token', response.data)
        self.assertEqual(response.data['state']['cloudFilters']['provider'], 'gcp')

    def test_save_requires_valid_manage_token(self):
        shared_view = HostInventorySharedView.objects.create(
            name='Shared view',
            state={'searchTerm': 'old'},
        )

        forbidden = self.client.post(
            f'{self.url}{shared_view.share_token}/save/',
            {'name': 'Updated name', 'state': {'searchTerm': 'new'}},
            format='json',
        )
        self.assertEqual(forbidden.status_code, status.HTTP_403_FORBIDDEN)

        allowed = self.client.post(
            f'{self.url}{shared_view.share_token}/save/',
            {
                'manage_token': shared_view.manage_token,
                'name': 'Updated name',
                'state': {'searchTerm': 'new'},
            },
            format='json',
        )

        self.assertEqual(allowed.status_code, status.HTTP_200_OK)
        shared_view.refresh_from_db()
        self.assertEqual(shared_view.name, 'Updated name')
        self.assertEqual(shared_view.state['searchTerm'], 'new')
        self.assertEqual(allowed.data['manage_token'], shared_view.manage_token)

    def test_delete_requires_valid_manage_token(self):
        shared_view = HostInventorySharedView.objects.create(
            name='Delete me',
            state={'searchTerm': 'delete'},
        )

        forbidden = self.client.post(f'{self.url}{shared_view.share_token}/delete/', {}, format='json')
        self.assertEqual(forbidden.status_code, status.HTTP_403_FORBIDDEN)

        allowed = self.client.post(
            f'{self.url}{shared_view.share_token}/delete/',
            {'manage_token': shared_view.manage_token},
            format='json',
        )
        self.assertEqual(allowed.status_code, status.HTTP_200_OK)
        self.assertFalse(HostInventorySharedView.objects.filter(id=shared_view.id).exists())


@override_settings(
    REQUIRE_API_KEY=True,
    SECRET_KEY='test-secret-key',
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
)
class HostInventorySharedViewApiAuthBypassTests(APITestCase):
    def test_create_remains_open_when_api_key_setting_enabled(self):
        response = self.client.post(
            '/api/host-inventory-view/',
            {'name': 'Open', 'state': {'searchTerm': 'open'}},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)