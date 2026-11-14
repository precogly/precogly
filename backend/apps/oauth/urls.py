from django.urls import path

from apps.oauth.views import PendingAuthorizationView

urlpatterns = [
    path(
        "pending-authorizations/<str:handle>/",
        PendingAuthorizationView.as_view(),
        name="pending-authorization",
    ),
]
