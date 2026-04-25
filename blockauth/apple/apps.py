from django.apps import AppConfig


class AppleAuthConfig(AppConfig):
    name = "blockauth.apple"
    label = "blockauth_apple"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        # Signal registration lands in Task 10.4 (pre_delete handler for
        # Apple revocation). Keeping ready() a no-op until then so the
        # AppConfig can be registered without depending on signals.py.
        pass
