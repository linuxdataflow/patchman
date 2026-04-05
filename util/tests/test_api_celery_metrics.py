from unittest.mock import Mock, patch

from django.contrib.auth.models import User
from django.test import override_settings
from rest_framework import status
from rest_framework.test import APITestCase


@override_settings(
    REQUIRE_API_KEY=False,
    CELERY_TASK_ALWAYS_EAGER=True,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
)
class CeleryMetricsAPITests(APITestCase):
    def setUp(self):
        self.url = '/api/celery-metrics/'
        self.user = User.objects.create_user(username='metrics', password='metrics-pass')
        self.client.force_authenticate(user=self.user)

    @patch('util.api_views.redis.Redis.from_url')
    @patch('util.api_views.celery_app.control.inspect')
    def test_returns_basic_metrics(self, mock_inspect_factory, mock_redis_from_url):
        inspector = Mock()
        inspector.stats.return_value = {
            'worker-a': {'pid': 1},
            'worker-b': {'pid': 2},
        }
        inspector.active.return_value = {
            'worker-a': [{'id': '1'}, {'id': '2'}],
            'worker-b': [{'id': '3'}],
        }
        mock_inspect_factory.return_value = inspector

        redis_client = Mock()
        redis_client.llen.return_value = 7
        mock_redis_from_url.return_value = redis_client

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['workers_count'], 2)
        self.assertEqual(response.data['jobs_in_progress'], 3)
        self.assertEqual(response.data['jobs_in_queue'], 7)

    @patch('util.api_views.redis.Redis.from_url')
    @patch('util.api_views.celery_app.control.inspect')
    def test_graceful_on_inspect_and_redis_failure(self, mock_inspect_factory, mock_redis_from_url):
        mock_inspect_factory.side_effect = RuntimeError('inspect unavailable')
        mock_redis_from_url.side_effect = RuntimeError('redis unavailable')

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNone(response.data['workers_count'])
        self.assertIsNone(response.data['jobs_in_progress'])
        self.assertIsNone(response.data['jobs_in_queue'])
