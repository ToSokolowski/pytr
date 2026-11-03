"""Encrypted storage for the login credentials and the session cookies.

Nothing secret is written to disk in plain text. A random 256-bit key is kept in the
operating system's keyring (Secret Service / KWallet on Linux, Keychain on macOS,
Credential Manager on Windows) and the files under ~/.pytr only hold AES-256-GCM
ciphertext under that key. The key goes to the keyring rather than the secrets
themselves because the session cookies are larger than some backends accept
(Windows Credential Manager: 2560 bytes per entry).

Without a usable keyring nothing is stored at all. There is deliberately no plain
text fallback: a session cookie on disk is as good as a completed 2FA login.

Files written by older versions of pytr (`credentials`, `cookies.<phone>.txt`) are
migrated to the encrypted format the first time they are read and then removed.
"""

import base64
import hashlib
import json
import os
import pathlib
import time
from http.cookiejar import Cookie, CookieJar, LoadError, MozillaCookieJar

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pytr.utils import get_logger, register_secret

BASE_DIR = pathlib.Path.home() / ".pytr"
CREDENTIALS_FILE = BASE_DIR / "credentials.enc"
LEGACY_CREDENTIALS_FILE = BASE_DIR / "credentials"

KEYRING_SERVICE = "pytr"
KEYRING_KEY_NAME = "storage-key"

_MAGIC = b"PYTR-ENC1"
_NONCE_SIZE = 12


class SecretStoreError(Exception):
    """The encrypted store can not be used: no keyring, a missing key or a damaged file."""


def _keyring():
    try:
        import keyring
        import keyring.errors
    except ImportError as e:
        raise SecretStoreError("The `keyring` package is not installed.") from e
    return keyring


def _get_key(create):
    keyring = _keyring()
    try:
        encoded = keyring.get_password(KEYRING_SERVICE, KEYRING_KEY_NAME)
        if encoded is None:
            if not create:
                return None
            encoded = base64.b64encode(os.urandom(32)).decode()
            keyring.set_password(KEYRING_SERVICE, KEYRING_KEY_NAME, encoded)
            # Read it back: some backends accept a write and then lose it.
            if keyring.get_password(KEYRING_SERVICE, KEYRING_KEY_NAME) != encoded:
                raise SecretStoreError("The keyring did not keep the storage key.")
    except keyring.errors.KeyringError as e:
        raise SecretStoreError(
            f"No usable keyring ({type(e).__name__}: {e}). On a desktop, unlock the keyring "
            "(GNOME Keyring, KWallet, ...). On a headless machine, don't store credentials."
        ) from e
    key = base64.b64decode(encoded)
    if len(key) != 32:
        raise SecretStoreError("The storage key in the keyring is malformed.")
    return key


def _ensure_private_dir(directory):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(directory, 0o700)


def _write_private_file(path, data):
    """Write `data` to `path`, readable by the owner only from the first byte on."""
    _ensure_private_dir(path.parent)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _remove_plaintext(path):
    """Delete a legacy plain text file, overwriting its contents first.

    Overwriting is best effort only: on SSDs, copy-on-write and journaling file
    systems the old blocks may survive. Full disk encryption is what covers those.
    """
    try:
        size = path.stat().st_size
        with open(path, "r+b") as f:
            f.write(b"\0" * size)
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass
    path.unlink(missing_ok=True)


def write_encrypted(path, plaintext, purpose):
    """Encrypt `plaintext` and store it at `path`. `purpose` binds the file to its use."""
    key = _get_key(create=True)
    nonce = os.urandom(_NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, _MAGIC + purpose.encode())
    _write_private_file(pathlib.Path(path), _MAGIC + nonce + ciphertext)


def read_encrypted(path, purpose):
    """Return the decrypted contents of `path`, or None if it does not exist."""
    path = pathlib.Path(path)
    try:
        blob = path.read_bytes()
    except FileNotFoundError:
        return None
    if not blob.startswith(_MAGIC) or len(blob) < len(_MAGIC) + _NONCE_SIZE + 16:
        raise SecretStoreError(f"{path} is not a pytr encrypted file.")
    key = _get_key(create=False)
    if key is None:
        raise SecretStoreError(f"The key for {path} is missing from the keyring; the file can not be decrypted.")
    nonce = blob[len(_MAGIC) : len(_MAGIC) + _NONCE_SIZE]
    try:
        return AESGCM(key).decrypt(nonce, blob[len(_MAGIC) + _NONCE_SIZE :], _MAGIC + purpose.encode())
    except InvalidTag:
        raise SecretStoreError(f"{path} was modified or encrypted with another key.") from None


# --- credentials -------------------------------------------------------------------


def store_credentials(phone_no, pin, path=None):
    path = pathlib.Path(path) if path else CREDENTIALS_FILE
    data = json.dumps({"phone_no": phone_no, "pin": pin}).encode()
    write_encrypted(path, data, "credentials")


def load_credentials(path=None):
    """Return `(phone_no, pin)` from the encrypted store, or None if nothing is stored.

    A credentials file left by an older pytr is moved into the encrypted store first.
    """
    path = pathlib.Path(path) if path else CREDENTIALS_FILE
    log = get_logger(__name__)
    if path == CREDENTIALS_FILE and not path.exists() and LEGACY_CREDENTIALS_FILE.is_file():
        lines = LEGACY_CREDENTIALS_FILE.read_text().splitlines()
        phone_no, pin = lines[0].strip(), lines[1].strip()
        register_secret(phone_no)
        try:
            store_credentials(phone_no, pin, path)
        except SecretStoreError as e:
            log.warning(f"Using the plain text credentials in {LEGACY_CREDENTIALS_FILE}: they can't be encrypted. {e}")
            return phone_no, pin
        _remove_plaintext(LEGACY_CREDENTIALS_FILE)
        log.warning(f"Moved the plain text credentials into the encrypted store {path}.")
        return phone_no, pin

    data = read_encrypted(path, "credentials")
    if data is None:
        return None
    creds = json.loads(data)
    register_secret(creds["phone_no"])
    return creds["phone_no"], creds["pin"]


def delete_credentials(path=None):
    (pathlib.Path(path) if path else CREDENTIALS_FILE).unlink(missing_ok=True)
    LEGACY_CREDENTIALS_FILE.unlink(missing_ok=True)


# --- cookies -----------------------------------------------------------------------


def cookies_file_for(phone_no):
    """The cookie file of a login. Named by a hash, so the file name doesn't give away the number."""
    digest = hashlib.sha256(phone_no.encode()).hexdigest()[:16]
    return BASE_DIR / f"cookies.{digest}.enc"


def legacy_cookies_file_for(phone_no):
    return BASE_DIR / f"cookies.{phone_no}.txt"


_COOKIE_FIELDS = (
    "version",
    "name",
    "value",
    "port",
    "port_specified",
    "domain",
    "domain_specified",
    "domain_initial_dot",
    "path",
    "path_specified",
    "secure",
    "expires",
    "discard",
    "comment",
    "comment_url",
    "rfc2109",
)


def _cookie_to_dict(cookie):
    d = {field: getattr(cookie, field) for field in _COOKIE_FIELDS}
    d["rest"] = dict(cookie._rest)  # type: ignore[attr-defined]
    return d


def _cookie_from_dict(d):
    kwargs = {field: d.get(field) for field in _COOKIE_FIELDS}
    kwargs["rfc2109"] = bool(kwargs["rfc2109"])
    return Cookie(rest=d.get("rest") or {}, **kwargs)


class EncryptedCookieJar(CookieJar):
    """A cookie jar with the `load`/`save` interface of MozillaCookieJar, stored encrypted."""

    def __init__(self, filename, legacy_filename=None):
        super().__init__()
        self.filename = pathlib.Path(filename)
        self.legacy_filename = pathlib.Path(legacy_filename) if legacy_filename else None

    def has_saved(self):
        return self.filename.exists() or bool(self.legacy_filename and self.legacy_filename.is_file())

    def save(self, filename=None, ignore_discard=False, ignore_expires=False):
        now = time.time()
        cookies = [
            _cookie_to_dict(c)
            for c in self
            if (ignore_discard or not c.discard) and (ignore_expires or not c.is_expired(now))
        ]
        write_encrypted(filename or self.filename, json.dumps(cookies).encode(), "cookies")
        if self.legacy_filename is not None and self.legacy_filename.exists():
            _remove_plaintext(self.legacy_filename)

    def load(self, filename=None, ignore_discard=False, ignore_expires=False):
        path = pathlib.Path(filename or self.filename)
        if not path.exists() and self.legacy_filename is not None and self.legacy_filename.is_file():
            self._load_legacy(ignore_discard, ignore_expires)
            return
        data = read_encrypted(path, "cookies")
        if data is None:
            raise FileNotFoundError(str(path))
        now = time.time()
        for d in json.loads(data):
            cookie = _cookie_from_dict(d)
            if not ignore_discard and cookie.discard:
                continue
            if not ignore_expires and cookie.is_expired(now):
                continue
            register_secret(cookie.value)
            self.set_cookie(cookie)

    def _load_legacy(self, ignore_discard, ignore_expires):
        legacy = MozillaCookieJar(str(self.legacy_filename))
        try:
            legacy.load(ignore_discard=ignore_discard, ignore_expires=ignore_expires)
        except LoadError as e:
            raise SecretStoreError(f"Could not read the old cookie file {self.legacy_filename}: {e}") from e
        for cookie in legacy:
            register_secret(cookie.value)
            self.set_cookie(cookie)
        # Re-encrypt right away so the plain text copy can go.
        log = get_logger(__name__)
        try:
            self.save(ignore_discard=True)
        except SecretStoreError as e:
            log.warning(f"The plain text session cookies in {self.legacy_filename} can't be encrypted. {e}")
            return
        log.warning("Moved the plain text session cookies into the encrypted store.")
