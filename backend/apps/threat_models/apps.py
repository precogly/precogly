from django.apps import AppConfig


class ThreatModelsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.threat_models"
    verbose_name = "Threat Models"

    def ready(self):
        import apps.threat_models.signals  # noqa: F401
