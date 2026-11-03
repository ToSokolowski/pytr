"""Secrets stay out of the logs, and what is stored on disk is encrypted."""

import io
import logging
import os
import stat
import time
from http.cookiejar import Cookie, MozillaCookieJar

import keyring
import keyring.backend
import keyring.backends.fail
import pytest

from pytr import credential_store, utils
from pytr.api import TradeRepublicApi
from pytr.credential_store import EncryptedCookieJar, SecretStoreError

PHONE = "+491701234567"
PIN = "4711"


class _MemoryKeyring(keyring.backend.KeyringBackend):
    priority = 1  # type: ignore[assignment]

    def __init__(self):
        super().__init__()
        self.entries = {}

    def get_password(self, service, username):
        return self.entries.get((service, username))

    def set_password(self, service, username, password):
        self.entries[(service, username)] = password

    def delete_password(self, service, username):
        self.entries.pop((service, username), None)


@pytest.fixture
def store(monkeypatch, tmp_path):
    """An empty credential store in tmp_path with an in-memory keyring."""
    base = tmp_path / "pytr"
    monkeypatch.setattr(credential_store, "BASE_DIR", base)
    monkeypatch.setattr(credential_store, "CREDENTIALS_FILE", base / "credentials.enc")
    monkeypatch.setattr(credential_store, "LEGACY_CREDENTIALS_FILE", base / "credentials")
    previous = keyring.get_keyring()
    ring = _MemoryKeyring()
    keyring.set_keyring(ring)
    yield ring
    keyring.set_keyring(previous)


@pytest.fixture
def captured_log():
    """Everything the api logger writes at DEBUG, through the same formatter as the CLI."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(utils.RedactingFormatter("%(message)s"))
    logger = logging.getLogger("api")
    logger.addHandler(handler)
    yield stream
    logger.removeHandler(handler)


# --- redaction ---------------------------------------------------------------------


def test_registered_secrets_are_redacted():
    utils.register_secret("waf-token-0123456789abcdef")
    assert utils.redact("token is waf-token-0123456789abcdef!") == f"token is {utils.REDACTED}!"


def test_short_values_are_not_redacted_by_substring():
    # Blanking a 4-digit PIN everywhere would reveal it through the holes it leaves.
    utils.register_secret(PIN)
    assert utils.redact("amount 47110.00") == "amount 47110.00"


@pytest.mark.parametrize(
    "text",
    [
        '{"phoneNumber": "+49170", "pin": "4711"}',
        "Cookie: tr_session=abc.def; tr_refresh=xyz",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl",
    ],
)
def test_credential_formats_are_redacted(text):
    redacted = utils.redact(text)
    for secret in ("4711", "+49170", "abc.def", "xyz", "eyJhbGciOiJIUzI1NiJ9"):
        assert secret not in redacted


def test_formatter_redacts_tracebacks():
    utils.register_secret("process-id-0123456789")
    try:
        raise ValueError("failed for url /login/process-id-0123456789/1234")
    except ValueError:
        record = logging.LogRecord("x", logging.ERROR, __file__, 1, "boom", None, exc_info=True)
        import sys

        record.exc_info = sys.exc_info()
    assert "process-id-0123456789" not in utils.RedactingFormatter().format(record)


def test_login_logs_no_secrets(captured_log, monkeypatch):
    class Response:
        status_code = 200
        headers: dict = {}

        def raise_for_status(self):
            pass

        def json(self):
            return {"processId": "0b6c1c8e-6a51-4b3c-9d1e-5f7a2b3c4d5e", "countdownInSeconds": 60}

    tr = TradeRepublicApi(phone_no=PHONE, pin=PIN, waf_token="aws-waf-token-value-0123456789", use_v2_login=False)
    monkeypatch.setattr(tr._websession, "post", lambda *a, **k: Response())

    tr.initiate_weblogin()

    output = captured_log.getvalue()
    assert output
    for secret in (PHONE, "aws-waf-token-value-0123456789", "0b6c1c8e-6a51-4b3c-9d1e-5f7a2b3c4d5e"):
        assert secret not in output


def test_websocket_payloads_stay_out_of_the_log_by_default(monkeypatch):
    monkeypatch.delenv(utils.ENV_LOG_PAYLOADS, raising=False)
    assert not utils.log_payloads()
    monkeypatch.setenv(utils.ENV_LOG_PAYLOADS, "1")
    assert utils.log_payloads()


# --- encrypted credentials ---------------------------------------------------------


def test_credentials_round_trip_encrypted(store):
    credential_store.store_credentials(PHONE, PIN)

    path = credential_store.CREDENTIALS_FILE
    data = path.read_bytes()
    assert PHONE.encode() not in data and PIN.encode() not in data
    assert credential_store.load_credentials() == (PHONE, PIN)
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_nothing_is_stored_without_a_keyring(store):
    keyring.set_keyring(keyring.backends.fail.Keyring())

    with pytest.raises(SecretStoreError):
        credential_store.store_credentials(PHONE, PIN)
    assert not credential_store.CREDENTIALS_FILE.exists()


def test_tampered_file_is_rejected(store):
    credential_store.store_credentials(PHONE, PIN)
    path = credential_store.CREDENTIALS_FILE
    data = bytearray(path.read_bytes())
    data[-1] ^= 1
    path.write_bytes(bytes(data))

    with pytest.raises(SecretStoreError):
        credential_store.load_credentials()


def test_file_is_bound_to_its_purpose(store):
    credential_store.write_encrypted(credential_store.CREDENTIALS_FILE, b"{}", "cookies")
    with pytest.raises(SecretStoreError):
        credential_store.load_credentials()


def test_lost_key_is_reported(store):
    credential_store.store_credentials(PHONE, PIN)
    store.entries.clear()

    with pytest.raises(SecretStoreError, match="missing from the keyring"):
        credential_store.load_credentials()


def test_legacy_credentials_are_migrated_and_removed(store):
    legacy = credential_store.LEGACY_CREDENTIALS_FILE
    legacy.parent.mkdir(parents=True)
    legacy.write_text(f"{PHONE}\n{PIN}\n")

    assert credential_store.load_credentials() == (PHONE, PIN)
    assert not legacy.exists()
    assert credential_store.CREDENTIALS_FILE.exists()
    assert credential_store.load_credentials() == (PHONE, PIN)


def test_legacy_credentials_stay_usable_without_a_keyring(store):
    keyring.set_keyring(keyring.backends.fail.Keyring())
    legacy = credential_store.LEGACY_CREDENTIALS_FILE
    legacy.parent.mkdir(parents=True)
    legacy.write_text(f"{PHONE}\n{PIN}\n")

    assert credential_store.load_credentials() == (PHONE, PIN)
    assert legacy.exists()


# --- encrypted cookies -------------------------------------------------------------


def _cookie(name, value):
    return Cookie(
        version=0,
        name=name,
        value=value,
        port=None,
        port_specified=False,
        domain=".traderepublic.com",
        domain_specified=True,
        domain_initial_dot=True,
        path="/",
        path_specified=True,
        secure=True,
        expires=int(time.time()) + 3600,
        discard=False,
        comment=None,
        comment_url=None,
        rest={"HttpOnly": ""},
    )


def test_cookie_file_name_does_not_contain_the_phone_number(store):
    assert PHONE not in str(credential_store.cookies_file_for(PHONE))


def test_cookies_round_trip_encrypted(store):
    path = credential_store.cookies_file_for(PHONE)
    jar = EncryptedCookieJar(path)
    jar.set_cookie(_cookie("tr_session", "session-cookie-value-0123456789"))
    jar.save(ignore_discard=True)

    assert b"session-cookie-value" not in path.read_bytes()
    loaded = EncryptedCookieJar(path)
    assert loaded.has_saved()
    loaded.load(ignore_discard=True)
    [cookie] = list(loaded)
    assert (cookie.name, cookie.value, cookie.domain, cookie.secure) == (
        "tr_session",
        "session-cookie-value-0123456789",
        ".traderepublic.com",
        True,
    )
    assert cookie.has_nonstandard_attr("HttpOnly")


def test_legacy_cookies_are_migrated_and_removed(store):
    legacy = credential_store.legacy_cookies_file_for(PHONE)
    legacy.parent.mkdir(parents=True)
    old = MozillaCookieJar(str(legacy))
    old.set_cookie(_cookie("tr_session", "legacy-cookie-value-0123456789"))
    old.save(ignore_discard=True)

    jar = EncryptedCookieJar(credential_store.cookies_file_for(PHONE), legacy)
    assert jar.has_saved()
    jar.load(ignore_discard=True)

    assert [c.value for c in jar] == ["legacy-cookie-value-0123456789"]
    assert not legacy.exists()
    assert credential_store.cookies_file_for(PHONE).exists()
