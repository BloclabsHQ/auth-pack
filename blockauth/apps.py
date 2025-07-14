from django.apps import AppConfig


class BlockAuthConfig(AppConfig):
    name = 'blockauth'
    verbose_name = 'Internal Authentication Module'
    default_auto_field = 'django.db.models.BigAutoField'

    def ready(self):
        import logging
        logging.basicConfig(level=logging.DEBUG)
        logger = logging.getLogger(__name__)
        logger.debug("BlockAuth service is ready")