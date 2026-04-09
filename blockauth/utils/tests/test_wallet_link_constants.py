from blockauth.constants import Features, URLNames


def test_wallet_link_feature_constant_exists():
    assert Features.WALLET_LINK == "WALLET_LINK"


def test_wallet_link_feature_in_all_features():
    assert "WALLET_LINK" in Features.all_features()


def test_wallet_link_url_name_constant_exists():
    assert URLNames.WALLET_LINK == "wallet-link"
