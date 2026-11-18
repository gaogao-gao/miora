import copy
from types import SimpleNamespace

import pytest

import core.client_manager as client_manager_mod
import core.jwt_utils as jwt_utils


@pytest.fixture
def jwt_state(monkeypatch):
    clock = SimpleNamespace(now=1_800_000_000.25)
    monkeypatch.setattr(jwt_utils, "time", SimpleNamespace(time=lambda: clock.now))
    monkeypatch.setattr(jwt_utils, "_CACHED_SECRET", None)
    monkeypatch.setattr(jwt_utils, "_CACHED_PASSWORD_FINGERPRINT", None)
    monkeypatch.setattr(jwt_utils, "_REVOKED_BEFORE_UNIX", 0)
    monkeypatch.delenv("JWT_SECRET", raising=False)
    jwt_utils.set_jwt_secret("jwt-revoke-regression-only-not-a-deployment-secret")
    return clock


def test_token_issued_right_after_revoke_in_same_second_is_valid(jwt_state):
    jwt_utils.set_admin_password_fingerprint("pbkdf2_sha256$260000$salt$old")
    old_token = jwt_utils.issue_jwt({"sub": "admin", "role": "admin"})

    # change-password: set the new fingerprint, revoke, then issue the response token, all in the same second.
    jwt_state.now += 0.5
    jwt_utils.set_admin_password_fingerprint("pbkdf2_sha256$260000$salt$new")
    jwt_utils.revoke_admin_jwts()
    new_token = jwt_utils.issue_jwt({"sub": "admin", "role": "admin"})

    assert jwt_utils.decode_jwt(old_token) is None
    assert jwt_utils.decode_jwt(new_token) is not None


def test_logout_then_login_in_same_second(jwt_state):
    before_logout = jwt_utils.issue_jwt({"sub": "admin", "role": "admin"})
    jwt_utils.revoke_admin_jwts()
    after_login = jwt_utils.issue_jwt({"sub": "admin", "role": "admin"})

    assert jwt_utils.decode_jwt(before_logout) is None
    assert jwt_utils.decode_jwt(after_login) is not None


def test_explicit_iat_is_still_checked_against_revocation(jwt_state):
    jwt_utils.revoke_admin_jwts(before_unix=2000)
    assert jwt_utils.decode_jwt(jwt_utils.issue_jwt({"sub": "admin", "role": "admin", "iat": 2000})) is None


@pytest.mark.asyncio
async def test_default_upstream_config_enables_http2_for_allowlisted_hosts(monkeypatch):
    import main as main_mod

    monkeypatch.delenv("HTTP2_ENABLED", raising=False)
    created = []

    class RecordingClient:
        def __init__(self, **kwargs):
            created.append(kwargs)

        async def aclose(self):
            pass

    monkeypatch.setattr(client_manager_mod.httpx, "AsyncClient", RecordingClient)

    manager = client_manager_mod.ClientManager()
    await manager.init(copy.deepcopy(main_mod.DEFAULT_UPSTREAM_CLIENT_CONFIG))
    async with manager.get_client("https://api.anthropic.com/v1/messages"):
        pass
    async with manager.get_client("https://relay.example.com/v1/chat/completions"):
        pass

    assert created[0].get("http2") is True
    assert not created[1].get("http2")
    assert created[0]["headers"]["User-Agent"] == "Miora"
