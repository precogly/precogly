from django.urls import path

from apps.oauth.views import (
    AuthorizedApplicationsView,
    AuthorizedApplicationView,
    DecisionView,
    PendingAuthorizationView,
)

urlpatterns = [
    path(
        "authorized-apps/",
        AuthorizedApplicationsView.as_view(),
        name="authorized-applications",
    ),
    path(
        "authorized-apps/<int:application_id>/",
        AuthorizedApplicationView.as_view(),
        name="authorized-application",
    ),
    path(
        "pending-authorizations/<str:handle>/",
        PendingAuthorizationView.as_view(),
        name="pending-authorization",
    ),
    path(
        "pending-authorizations/<str:handle>/decision/",
        DecisionView.as_view(),
        name="pending-authorization-decision",
    ),
]
