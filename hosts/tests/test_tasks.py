from unittest.mock import patch

from django.test import TestCase, override_settings
from django.utils import timezone

from arch.models import MachineArchitecture
from domains.models import Domain
from hosts.models import Host
from hosts.tasks import check_all_hosts_rdns, check_host_rdns
from operatingsystems.models import OSRelease, OSVariant


@override_settings(
    CELERY_TASK_ALWAYS_EAGER=True,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}}
)
class HostTasksTests(TestCase):
    def setUp(self):
        self.arch = MachineArchitecture.objects.create(name='x86_64')
        self.domain = Domain.objects.create(name='example.com')
        self.os_release = OSRelease.objects.create(name='Ubuntu 22.04')
        self.os_variant = OSVariant.objects.create(
            name='Ubuntu 22.04.3 LTS',
            osrelease=self.os_release,
            arch=self.arch,
        )

    def _create_host(self, hostname, ip):
        return Host.objects.create(
            hostname=hostname,
            ipaddress=ip,
            osvariant=self.os_variant,
            kernel='5.15.0-91-generic',
            arch=self.arch,
            domain=self.domain,
            lastreport=timezone.now(),
        )

    def test_check_host_rdns_calls_model_method(self):
        host = self._create_host('rdns-single.example.com', '192.168.1.220')

        with patch.object(Host, 'check_rdns') as mock_check_rdns:
            check_host_rdns(host.id)

        mock_check_rdns.assert_called_once()

    @patch('hosts.tasks.check_host_rdns')
    def test_check_all_hosts_rdns_queues_each_host(self, mock_check_host_rdns):
        host1 = self._create_host('rdns1.example.com', '192.168.1.221')
        host2 = self._create_host('rdns2.example.com', '192.168.1.222')

        check_all_hosts_rdns()

        mock_check_host_rdns.delay.assert_any_call(host1.id)
        mock_check_host_rdns.delay.assert_any_call(host2.id)
        self.assertEqual(mock_check_host_rdns.delay.call_count, 2)
