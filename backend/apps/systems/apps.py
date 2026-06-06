from django.apps import AppConfig


class SystemsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.systems"
    verbose_name = "Systems"

    def ready(self):
        # Import signals to register them
        import apps.systems.signals  # noqa: F401
