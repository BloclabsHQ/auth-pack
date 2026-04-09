from blockauth.constants import Features, URLNames


def test_wallet_link_feature_constant_exists():
    assert Features.WALLET_LINK == "WALLET_LINK"


def test_wallet_link_feature_in_all_features():
    assert "WALLET_LINK" in Features.all_features()


def test_wallet_link_url_name_constant_exists():
    assert URLNames.WALLET_LINK == "wallet-link"


from blockauth.triggers import DummyPostWalletLinkTrigger
from blockauth.utils.config import get_config


def test_dummy_post_wallet_link_trigger_is_no_op():
    trigger = DummyPostWalletLinkTrigger()
    trigger.trigger(context={"user": {}, "wallet_address": "0xabc"})  # must not raise


def test_post_wallet_link_trigger_resolves_from_config():
    trigger_class = get_config("POST_WALLET_LINK_TRIGGER")
    assert trigger_class is DummyPostWalletLinkTrigger
