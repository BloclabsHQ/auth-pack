from django.test import override_settings

from blockauth.utils.outbound_http import get_social_outbound_timeout


def test_social_outbound_timeout_defaults_to_connect_read_tuple():
    with override_settings(BLOCK_AUTH_SETTINGS={}):
        assert get_social_outbound_timeout() == (3.05, 10)


def test_social_outbound_timeout_reads_runtime_setting():
    with override_settings(
        BLOCK_AUTH_SETTINGS={"SOCIAL_OUTBOUND_TIMEOUT": [1.5, 4]}
    ):
        assert get_social_outbound_timeout() == (1.5, 4)
