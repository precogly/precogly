"""
URL routing for threat_models app.
"""

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    AssumptionViewSet,
    BlueprintViewSet,
    BusinessObjectiveViewSet,
    OutOfScopeItemViewSet,
    ThreatModelReferenceImageViewSet,
    ThreatModelViewSet,
    UseCaseViewSet,
)

router = DefaultRouter()
router.register(r"threat-models", ThreatModelViewSet, basename="threat-model")

# Nested route for the structural models of a threat model
router.register(
    r"threat-models/(?P<threat_model_pk>\d+)/blueprints",
    BlueprintViewSet,
    basename="threat-model-blueprints",
)

router.register(
    r"threat-models/(?P<threat_model_pk>\d+)/assumptions",
    AssumptionViewSet,
    basename="threat-model-assumptions",
)
router.register(
    r"threat-models/(?P<threat_model_pk>\d+)/business-objectives",
    BusinessObjectiveViewSet,
    basename="threat-model-business-objectives",
)
router.register(
    r"threat-models/(?P<threat_model_pk>\d+)/use-cases",
    UseCaseViewSet,
    basename="threat-model-use-cases",
)

# Nested route for threat model reference images
router.register(
    r"threat-models/(?P<threat_model_pk>\d+)/reference-images",
    ThreatModelReferenceImageViewSet,
    basename="threat-model-reference-images",
)

# Nested route for out-of-scope items
router.register(
    r"threat-models/(?P<threat_model_pk>\d+)/out-of-scope-items",
    OutOfScopeItemViewSet,
    basename="threat-model-out-of-scope-items",
)

# Direct route for individual image operations
router.register(
    r"reference-images",
    ThreatModelReferenceImageViewSet,
    basename="reference-images",
)

urlpatterns = [
    path("", include(router.urls)),
]
