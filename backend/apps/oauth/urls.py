from django.urls import path

from apps.oauth.views import (
    ConnectedApplicationsView,
    ConnectedApplicationView,
    DecisionView,
    PendingAuthorizationView,
)

urlpatterns = [
    path(
        "connected-apps/",
        ConnectedApplicationsView.as_view(),
        name="connected-applications",
    ),
    path(
        "connected-apps/<int:application_id>/",
        ConnectedApplicationView.as_view(),
        name="connected-application",
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
