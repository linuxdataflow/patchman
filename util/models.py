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

import secrets

from django.db import models


def _generate_token():
    return secrets.token_urlsafe(24)


class HostInventorySharedView(models.Model):
    name = models.CharField(max_length=255, default='Shared view')
    state = models.JSONField(default=dict)
    share_token = models.CharField(max_length=64, unique=True, db_index=True, editable=False)
    manage_token = models.CharField(max_length=64, unique=True, db_index=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name', '-updated_at']

    def save(self, *args, **kwargs):
        if not self.share_token:
            self.share_token = _generate_token()
        if not self.manage_token:
            self.manage_token = _generate_token()
        super().save(*args, **kwargs)

    def __str__(self):
        return f'{self.name} ({self.share_token})'