from blockauth.utils.custom_exception import WalletConflictError


def test_wallet_conflict_error_has_409_status():
    assert WalletConflictError.status_code == 409


def test_wallet_conflict_error_is_raised_with_detail():
    error = WalletConflictError(detail="This wallet address is already linked to another account.")
    assert error.status_code == 409
    assert "already linked" in str(error.detail)
