"""
URL routing for compliance app.
"""

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .matrix import ComplianceMatrixApiView, compliance_matrix_html
from .views import (
    CountermeasureLibraryStandardViewSet,
    StandardFrameworkViewSet,
    StandardRequirementViewSet,
)

router = DefaultRouter()
router.register(r"frameworks", StandardFrameworkViewSet, basename="framework")
router.register(r"requirements", StandardRequirementViewSet, basename="requirement")
router.register(
    r"countermeasure-standards",
    CountermeasureLibraryStandardViewSet,
    basename="countermeasure-standard",
)

urlpatterns = [
    path("", include(router.urls)),
    path(
        "threat-models/<int:tm_id>/compliance-matrix/",
        ComplianceMatrixApiView.as_view(),
        name="compliance-matrix",
    ),
    path(
        "threat-models/<int:tm_id>/compliance-matrix.html",
        compliance_matrix_html,
        name="compliance-matrix-html",
    ),
]
