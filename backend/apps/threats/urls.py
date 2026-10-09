"""
URL routing for threats app.
"""

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    ComponentLibraryThreatViewSet,
    CountermeasureCommentViewSet,
    CountermeasureLibraryViewSet,
    ExternalTaxonomyViewSet,
    InstanceCountermeasureStandardViewSet,
    InstanceCountermeasureViewSet,
    InstanceThreatTaxonomyEntryViewSet,
    InstanceThreatViewSet,
    PentestFindingViewSet,
    RiskResponseViewSet,
    RiskViewSet,
    ScoringMethodsView,
    TaxonomyEntryViewSet,
    ThreatLibraryViewSet,
    ThreatPersonaViewSet,
    ThreatSourceViewSet,
    VerificationTestViewSet,
)

router = DefaultRouter()
router.register(r"threat-library", ThreatLibraryViewSet, basename="threat-library")
router.register(
    r"countermeasure-library",
    CountermeasureLibraryViewSet,
    basename="countermeasure-library",
)
router.register(
    r"component-library-threats",
    ComponentLibraryThreatViewSet,
    basename="component-library-threat",
)
# One table for every scenario, whatever it targets (plan section 4.1).
router.register(r"threats", InstanceThreatViewSet, basename="threat")
router.register(
    r"countermeasures",
    InstanceCountermeasureViewSet,
    basename="countermeasure",
)
router.register(
    r"verification-tests",
    VerificationTestViewSet,
    basename="verification-test",
)
router.register(
    r"pentest-findings",
    PentestFindingViewSet,
    basename="pentest-finding",
)
router.register(
    r"instance-countermeasure-standards",
    InstanceCountermeasureStandardViewSet,
    basename="instance-countermeasure-standard",
)

router.register(
    r"countermeasure-comments",
    CountermeasureCommentViewSet,
    basename="countermeasure-comment",
)

router.register(
    r"threat-taxonomy-entries",
    InstanceThreatTaxonomyEntryViewSet,
    basename="threat-taxonomy-entry",
)

router.register(r"taxonomies", ExternalTaxonomyViewSet, basename="taxonomy")
router.register(r"taxonomy-entries", TaxonomyEntryViewSet, basename="taxonomy-entry")

# Nested routes under threat models
router.register(
    r"threat-models/(?P<threat_model_pk>\d+)/risks",
    RiskViewSet,
    basename="threat-model-risk",
)
router.register(
    r"threat-models/(?P<threat_model_pk>\d+)/risks/(?P<risk_pk>\d+)/responses",
    RiskResponseViewSet,
    basename="threat-model-risk-response",
)
router.register(
    r"threat-models/(?P<threat_model_pk>\d+)/threat-personas",
    ThreatPersonaViewSet,
    basename="threat-model-persona",
)

# Global reference data
router.register(r"threat-sources", ThreatSourceViewSet, basename="threat-source")

urlpatterns = [
    path("scoring-methods/", ScoringMethodsView.as_view(), name="scoring-methods"),
    path("", include(router.urls)),
]
