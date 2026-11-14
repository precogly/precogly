from django.urls import path

from apps.oauth.views import DecisionView, PendingAuthorizationView

urlpatterns = [
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
