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

from django.db.models.signals import m2m_changed
from django.dispatch import receiver

from hosts.models import Host


@receiver(m2m_changed, sender=Host.packages.through)
def update_host_packages_count(sender, instance, action, **kwargs):
    """Update packages_count when Host.packages M2M changes."""
    if action in ('post_add', 'post_remove', 'post_clear'):
        instance.packages_count = instance.packages.count()
        instance.save(update_fields=['packages_count'])


@receiver(m2m_changed, sender=Host.updates.through)
def update_host_updates_count(sender, instance, action, **kwargs):
    """Update calculated and legacy update counters when Host.updates M2M changes."""
    if action in ('post_add', 'post_remove', 'post_clear'):
        calc_sec_count = instance.updates.filter(security=True).count()
        calc_bug_count = instance.updates.filter(security=False).count()
        instance.calc_sec_updates_count = calc_sec_count
        instance.calc_bug_updates_count = calc_bug_count
        # Legacy fields are kept for compatibility and mirror calculated values.
        instance.sec_updates_count = calc_sec_count
        instance.bug_updates_count = calc_bug_count
        instance.save(update_fields=[
            'calc_sec_updates_count',
            'calc_bug_updates_count',
            'sec_updates_count',
            'bug_updates_count',
        ])


@receiver(m2m_changed, sender=Host.errata.through)
def update_host_errata_count(sender, instance, action, **kwargs):
    """Update errata_count when Host.errata M2M changes."""
    if action in ('post_add', 'post_remove', 'post_clear'):
        instance.errata_count = instance.errata.count()
        instance.save(update_fields=['errata_count'])
