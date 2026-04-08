from rest_framework.permissions import BasePermission, IsAuthenticatedOrReadOnly
from rest_framework_api_key.permissions import HasAPIKey


class HasAPIKeyOrIsAuthenticatedOrReadOnly(BasePermission):
    """
    Allow access with a valid API key, or fall back to IsAuthenticatedOrReadOnly
    for session/browser flows (authenticated writes, unauthenticated reads).

    This lets the Rundeck plugin authenticate via an API key sent as
    'Authorization: Api-Key <token>' while the browser UI continues to work
    through OAuth2/session authentication unchanged.
    """

    def has_permission(self, request, view):
        return (
            HasAPIKey().has_permission(request, view)
            or IsAuthenticatedOrReadOnly().has_permission(request, view)
        )
