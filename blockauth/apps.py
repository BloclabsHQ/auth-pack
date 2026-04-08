from django.apps import AppConfig


class BlockAuthConfig(AppConfig):
    name = "blockauth"
    verbose_name = "BlockAuth"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        pass
