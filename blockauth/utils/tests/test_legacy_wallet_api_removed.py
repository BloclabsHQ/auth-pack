"""SEC-05: the legacy wallet login module and serializer are gone."""

import importlib

import pytest

import blockauth.serializers.wallet_serializers as wallet_serializers


def test_legacy_wallet_module_is_removed():
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("blockauth.utils.web3.wallet")


def test_legacy_wallet_login_serializer_is_removed():
    assert not hasattr(wallet_serializers, "WalletLoginSerializer")
