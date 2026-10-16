"""
URL routing for systems app.
"""

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    BoundaryViewSet,
    ComponentDataAssetViewSet,
    ComponentLibraryViewSet,
    DataAssetViewSet,
    FlowAssetViewSet,
    FlowViewSet,
    IntegrationSourceViewSet,
    OrgsystemComponentViewSet,
    OrgsystemViewSet,
    ZoneViewSet,
)

router = DefaultRouter()
router.register(r"systems", OrgsystemViewSet, basename="orgsystem")
router.register(r"zones", ZoneViewSet, basename="zone")
router.register(r"boundaries", BoundaryViewSet, basename="boundary")
router.register(
    r"component-library", ComponentLibraryViewSet, basename="component-library"
)
router.register(r"components", OrgsystemComponentViewSet, basename="component")
router.register(r"data-assets", DataAssetViewSet, basename="data-asset")
router.register(r"flows", FlowViewSet, basename="flow")
router.register(r"integrations", IntegrationSourceViewSet, basename="integration")
router.register(
    r"component-data-assets", ComponentDataAssetViewSet, basename="component-data-asset"
)
router.register(r"flow-assets", FlowAssetViewSet, basename="flow-asset")

urlpatterns = [
    path("", include(router.urls)),
]
