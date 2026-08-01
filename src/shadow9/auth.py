"""
Authentication module for Shadow9 SOCKS5 proxy.

Provides secure credential management using Argon2id hashing
and secure token generation.
"""

import os
import secrets
import json
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional
from dataclasses import dataclass, asdict, field, fields, replace
from datetime import datetime, UTC

from argon2 import PasswordHasher, extract_parameters
from argon2.exceptions import VerifyMismatchError, InvalidHash
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

import structlog

from .paths import lock_file, read_or_create_salt, resolve_salt_file, write_file_safely
from .wireguard.addresses import TunnelNetwork, parse_address, parse_network
from .wireguard.keys import derive_public_key, is_valid_key
from .wireguard.render import PeerRole

logger = structlog.get_logger(__name__)

# Hashed on the branches that reject a login without checking a real hash, so every
# outcome costs the same and the response time does not reveal which users exist.
_DUMMY_PASSWORD = "dummy_password_for_timing"

# Set this to say the store may keep its users as plain JSON, which is what happens when
# there is no master key to encrypt them with. An install never sets it.
ALLOW_PLAINTEXT_ENV = "SHADOW9_ALLOW_PLAINTEXT_CREDENTIALS"

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})


class MissingMasterKey(Exception):
    """A credential store was opened with no key to encrypt its users with."""


def plaintext_credentials_allowed() -> bool:
    """
    Whether this process may keep credentials on disk as plain JSON.

    One thing says yes: SHADOW9_ALLOW_PLAINTEXT_CREDENTIALS. A developer sets it by hand
    to work without a key, and tests/conftest.py sets it for the test suite, which builds
    most of its stores without one. Nothing in the package sets it, so an installed copy
    that has lost its master key cannot fall through to writing plaintext.

    Returns:
        True if a store with no master key may be built, False otherwise
    """
    return os.getenv(ALLOW_PLAINTEXT_ENV, "").strip().lower() in _TRUE_VALUES


def _no_master_key_message(credentials_file: Path) -> str:
    """What to tell an operator whose store has no key to encrypt with.

    Which advice is right turns on whether a file is already there. On a fresh install the
    operator wants a key generated. Where a store already exists, generating one is the
    worst thing they can do: the existing file is then read with the new key, fails, and
    the store comes up with nobody in it. A key on its own is not enough to read it back
    either, because the encryption key is derived from the master key and the salt in
    .salt together, so a regenerated salt locks the file exactly as thoroughly as a lost
    key does.
    """
    if not credentials_file.exists():
        return (
            f"No master key, so {credentials_file} cannot be encrypted. Set "
            f"SHADOW9_MASTER_KEY, or put it in the install's .env file, and run "
            f"'shadow9 master-key generate' if there is no key yet."
        )

    return (
        f"No master key, so {credentials_file} cannot be read or written. A store is "
        f"already there, so set the SHADOW9_MASTER_KEY it was written with rather than "
        f"generating a new one, and keep the .salt file beside it, because the key and "
        f"the salt together are what decrypt it. Generating a new key would leave every "
        f"user in that file unreadable."
    )


@dataclass
class Credential:
    """Represents a user credential with all connection settings."""

    username: str
    password_hash: str
    created_at: str
    last_used: Optional[str] = None
    enabled: bool = True

    # Routing settings
    use_tor: bool = True  # Whether to route this user's traffic through Tor
    bridge_type: str = "none"  # none, obfs4, snowflake

    # Security settings
    security_level: str = "basic"  # none, basic, moderate, paranoid

    # Restrictions
    allowed_ports: Optional[list[int]] = None  # None = all ports allowed
    rate_limit: Optional[int] = None  # None = use server default

    # Per-user bind address (optional)
    bind_port: Optional[int] = None  # None = use shared server port

    # Privacy settings
    logging_enabled: bool = (
        True  # When False, no user activity is logged  # None = use shared server port
    )

    # WireGuard peer settings. All of them absent means this user is not a peer, which is
    # what every user is until somebody enrolls one. A peer lives on the user record
    # rather than in a file of its own so that enable, disable and remove already work on
    # it and there is nothing to leave behind when a user is deleted.
    wg_public_key: Optional[str] = None  # Base64 X25519 public key, 44 characters
    wg_address: Optional[str] = None  # This peer's address inside the tunnel, no prefix
    wg_routes: Optional[list[str]] = None  # Subnets reachable through this peer, CIDR
    wg_role: Optional[str] = None  # hub, node or device
    wg_endpoint: Optional[str] = None  # host:port other peers dial. Only the hub has one
    wg_keepalive: Optional[int] = None  # Seconds between keepalives, or None for silence
    wg_expires_at: Optional[str] = None  # When this peer stops being allowed in
    wg_private_key: Optional[str] = field(default=None, repr=False)
    wg_refresh_key: Optional[str] = field(default=None, repr=False)
    wg_full_tunnel: Optional[bool] = None
    wg_obfuscated: Optional[bool] = None

    # Keys read out of the file that this version has no field for. Kept so that the next
    # write puts them back rather than dropping them, which is what makes a downgrade
    # survivable: see _record_for_file. Never written to the file under this name.
    unknown_fields: dict[str, object] = field(default_factory=dict)


# The names this version knows. The box that unknown keys are kept in is deliberately not
# one of them: nothing is written to the file under that name, and a caller handing over
# field names it got from an API schema must not be able to write arbitrary keys into a
# record. A name this record does not have is ignored rather than attached and written.
_CREDENTIAL_FIELDS = frozenset(
    field.name for field in fields(Credential) if field.name != "unknown_fields"
)

# The peer settings, named once so the load check and the write both cover the same seven.
_WIREGUARD_FIELDS = (
    "wg_public_key",
    "wg_address",
    "wg_routes",
    "wg_role",
    "wg_endpoint",
    "wg_keepalive",
    "wg_expires_at",
    "wg_private_key",
    "wg_refresh_key",
    "wg_full_tunnel",
    "wg_obfuscated",
)


@dataclass(frozen=True)
class _FileVersion:
    """What tells one version of the credentials file apart from the next.

    A modification time on its own is not enough. A filesystem that records whole seconds
    reports the same time for a replacement that lands in the same second as the read
    before it, and nothing later ever changes that time back, so the change is missed for
    good rather than picked up a moment late. The size and the file's identity move when
    the timestamp does not.
    """

    mtime_ns: int
    size: int
    identity: int


def _file_version(path: Path) -> Optional[_FileVersion]:
    """Read the identity of the file at `path`, or None when there is no file there."""
    try:
        stat = path.stat()
    except OSError:
        return None

    return _FileVersion(mtime_ns=stat.st_mtime_ns, size=stat.st_size, identity=stat.st_ino)


# The values these two fields are allowed to hold, named once so the check a new user
# passes and the check a stored record passes cannot drift apart.
_BRIDGE_TYPES = frozenset(("none", "obfs4", "snowflake"))
_SECURITY_LEVELS = frozenset(("none", "basic", "moderate", "paranoid"))


def _is_whole_number(value: object) -> bool:
    """True for an integer, and not for a bool, which is one as far as isinstance is concerned."""
    return isinstance(value, int) and not isinstance(value, bool)


def _utc_now_text() -> str:
    """The time now, written the way this store's timestamps have always been written.

    datetime.utcnow() is deprecated and due for removal. The timezone-aware call that
    replaces it renders a "+00:00" offset, and these strings are not private to one run:
    they go into credentials.enc and come back out of it, so an install upgraded to the
    aware call would end up holding both shapes in one file. _apply_pending_last_used
    decides which of two logins is the later one by comparing that text, and an offset
    sorts after every digit, so a stamp carrying one would look newer than every stamp
    without one whatever the clock said. Dropping the offset keeps the stored bytes
    identical to what is already on disk.
    """
    return datetime.now(UTC).replace(tzinfo=None).isoformat()


def _checked_timestamp(value: object, field: str) -> str:
    """The time `value` names, written the way this store writes times.

    Accepting a time and trusting its text are two different things, and only checking it
    parses left the second one unearned. Comparisons here are made on the text: a stamp
    reading 13:00:00+02:00 is 11:00 UTC, but it sorts after every stamp written without an
    offset, so a login an hour earlier looked like the later one and won. The same goes
    for a space where the T belongs, which sorts before every canonical stamp of the same
    day. Neither shape is written here, but a file repaired by hand or left behind by a
    version that used the timezone-aware clock holds them, and they compare wrong for as
    long as they stay.

    So every accepted time is converted to UTC and rendered the one way, at the edge where
    the file comes in, rather than each comparison having to parse its way out of the
    problem. A stamp already in that shape comes back byte for byte identical, which is
    what keeps credentials.enc looking the way it always has.

    Args:
        value: The field as it came out of the file
        field: The field's name, for the message

    Returns:
        The same time, in the shape this store writes

    Raises:
        ValueError: when `value` is not a time at all
    """
    if not isinstance(value, str):
        raise ValueError(f"{field} is {type(value).__name__}, not a time")
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        raise ValueError(f"{field} is not a time: {value!r}") from None

    if moment.tzinfo is not None:
        moment = moment.astimezone(UTC).replace(tzinfo=None)

    return moment.isoformat()


def _checked_port(value: object, field: str) -> None:
    """Raise unless `value` is a port a socket could be asked for."""
    if not _is_whole_number(value) or not 1 <= int(value) <= 65535:
        raise ValueError(f"{field} is not a port: {value!r}")


def _checked_password_hash(value: object, username: str) -> None:
    """Raise unless `value` is an encoded hash this store's verifier could read.

    Any nonempty string used to pass. A record holding "x" then loaded clean, left
    load_error unset, and failed only when that user tried to log in, which is a long way
    from the file that caused it and a long time after the operator could have fixed it.

    The check is exactly what verify() can consume: the encoded argon2 structure, parsed
    the same way the hasher parses it. It says nothing about the cost parameters, because
    a hash made with parameters this store has moved on from is a hash it deliberately
    accepts and rehashes on the next successful login.

    Args:
        value: The field as it came out of the file
        username: The name the record is filed under, for the message

    Raises:
        ValueError: when nothing could ever verify a password against this
    """
    if not isinstance(value, str) or not value:
        raise ValueError(f"{username} has no password hash")

    try:
        extract_parameters(value)
    except InvalidHash:
        raise ValueError(f"{username} has a password hash nothing can verify") from None


def _checked_credential(
    username: str, record: dict[str, object], tunnel_network: TunnelNetwork
) -> Credential:
    """
    Build one stored record, rejecting anything the rest of the system cannot use.

    JSON that parses is not the same as a record that works. A rate limit of zero, a
    bridge type nothing implements or a created_at that is not a time all load happily
    into a dataclass and then raise at the API's model instead, a long way from the file
    that caused it, while the store goes on believing it read the file and lets a change
    rewrite it. Refusing here puts the failure where the bad bytes are and leaves
    load_error set, which is what stops a write replacing the file.

    A key this version has no field for is the one thing that is not refused. Passing the
    whole record to the dataclass raised TypeError on any such key, which failed the load,
    which stopped every write: a file written by a later version left an older one unable
    to save at all, and the only sign of it was an "unexpected keyword argument" in a log.
    Those keys are set aside instead and written back by the next save, so a version that
    does not understand a setting neither refuses to run nor quietly deletes it.

    Args:
        username: The name the record is filed under
        record: The record's fields as they came out of the file

    Returns:
        The stored record

    Raises:
        ValueError: when a field holds something this store would never have written
    """
    credential = Credential(
        **{name: value for name, value in record.items() if name in _CREDENTIAL_FIELDS}
    )
    credential.unknown_fields = {
        name: value for name, value in record.items() if name not in _CREDENTIAL_FIELDS
    }

    if credential.username != username:
        raise ValueError(
            f"record filed under {username!r} names itself {credential.username!r}"
        )

    if not AuthManager._validate_username(credential.username):
        raise ValueError(f"username is not a valid name: {credential.username!r}")

    _checked_password_hash(credential.password_hash, username)

    # written back, not just checked: the record carries these into comparisons that read
    # them as text, so the shape has to be settled before it reaches the table
    credential.created_at = _checked_timestamp(credential.created_at, "created_at")
    if credential.last_used is not None:
        credential.last_used = _checked_timestamp(credential.last_used, "last_used")

    for name in ("enabled", "use_tor", "logging_enabled"):
        if not isinstance(getattr(credential, name), bool):
            raise ValueError(f"{name} is not true or false: {getattr(credential, name)!r}")

    if credential.bridge_type not in _BRIDGE_TYPES:
        raise ValueError(f"bridge_type is not a bridge: {credential.bridge_type!r}")

    if credential.security_level not in _SECURITY_LEVELS:
        raise ValueError(f"security_level is not a level: {credential.security_level!r}")

    if credential.allowed_ports is not None:
        if not isinstance(credential.allowed_ports, list):
            raise ValueError(f"allowed_ports is not a list: {credential.allowed_ports!r}")
        for port in credential.allowed_ports:
            _checked_port(port, "allowed_ports")

    if credential.rate_limit is not None and (
        not _is_whole_number(credential.rate_limit) or credential.rate_limit < 1
    ):
        raise ValueError(f"rate_limit is not a limit: {credential.rate_limit!r}")

    if credential.bind_port is not None:
        _checked_port(credential.bind_port, "bind_port")

    _check_peer_fields(credential, tunnel_network)

    return credential


def _check_peer_fields(credential: Credential, tunnel_network: TunnelNetwork) -> None:
    """Raise unless this record's WireGuard settings are ones the tunnel could be built from.

    Each check is the one the code that consumes the value already uses, imported rather
    than rewritten, because two definitions of "a valid key" drift apart and the drift only
    shows up as a tunnel that will not come up. parse_network in particular refuses host
    bits, so 192.168.1.1/24 is an error here and not a silent 192.168.1.0/24, which are
    different subnets and decide which traffic crosses the tunnel.

    What cannot be checked here is that no two peers hold the same tunnel address. This
    sees one record, and WireGuard hands a duplicated address to the newer peer without an
    error while the older one silently loses it, so whatever adds a peer has to call
    wireguard.addresses.claim_address against every other peer's address first.

    Args:
        credential: The record to check, already built

    Raises:
        ValueError: when a peer setting is not something a config could be rendered from
    """
    key = credential.wg_public_key
    if key is not None and (not isinstance(key, str) or not is_valid_key(key)):
        raise ValueError(f"wg_public_key is not a WireGuard public key: {key!r}")

    private_key = credential.wg_private_key
    if private_key is not None:
        if not isinstance(private_key, str) or not is_valid_key(private_key):
            raise ValueError("wg_private_key is not a WireGuard private key")
        if key is not None and derive_public_key(private_key) != key:
            raise ValueError("wg_private_key does not match wg_public_key")

    refresh_key = credential.wg_refresh_key
    if refresh_key is not None:
        if not isinstance(refresh_key, str):
            raise ValueError("wg_refresh_key is not a refresh key")
        try:
            decoded_refresh_key = bytes.fromhex(refresh_key)
        except ValueError:
            raise ValueError("wg_refresh_key is not a refresh key") from None
        if len(decoded_refresh_key) != 32:
            raise ValueError("wg_refresh_key is not a refresh key")

    for name in ("wg_full_tunnel", "wg_obfuscated"):
        value = getattr(credential, name)
        if value is not None and not isinstance(value, bool):
            raise ValueError(f"{name} is not true or false: {value!r}")

    if credential.wg_address is not None:
        if not isinstance(credential.wg_address, str):
            raise ValueError(f"wg_address is not an address: {credential.wg_address!r}")
        # a plain address, so a prefix is refused: 10.9.0.2/24 is a range and this field
        # names one host in the tunnel
        address = parse_address(credential.wg_address)
        if address not in tunnel_network:
            raise ValueError(
                f"wg_address {address} is outside tunnel network {tunnel_network}"
            )

    if credential.wg_routes is not None:
        if not isinstance(credential.wg_routes, list):
            raise ValueError(f"wg_routes is not a list: {credential.wg_routes!r}")
        for route in credential.wg_routes:
            if not isinstance(route, str):
                raise ValueError(f"wg_routes holds something that is not a network: {route!r}")
            parse_network(route)

    if credential.wg_role is not None:
        try:
            PeerRole(credential.wg_role)
        except ValueError:
            raise ValueError(f"wg_role is not a role: {credential.wg_role!r}") from None

    if credential.wg_endpoint is not None and (
        not isinstance(credential.wg_endpoint, str) or not credential.wg_endpoint
    ):
        raise ValueError(f"wg_endpoint is not an endpoint: {credential.wg_endpoint!r}")

    if credential.wg_keepalive is not None and (
        not _is_whole_number(credential.wg_keepalive) or not 1 <= credential.wg_keepalive <= 65535
    ):
        raise ValueError(f"wg_keepalive is not an interval: {credential.wg_keepalive!r}")

    if credential.wg_expires_at is not None:
        # written back like the other two times this record holds, so an expiry compares
        # against them as text without either side having to parse its way out of an offset
        credential.wg_expires_at = _checked_timestamp(credential.wg_expires_at, "wg_expires_at")


def _record_for_file(credential: Credential) -> dict[str, object]:
    """One stored record as it is written to the file.

    Two things happen here that asdict on its own does not do, and both are about what an
    older version of this store can still read.

    A peer setting that is not set is left out rather than written as null. Almost nobody
    is a WireGuard peer, and a record with no wg_ keys in it is a record every version of
    this store can read, so adding these fields does not by itself make an install's file
    unreadable by the version before this one. Enrolling the first peer is what does that,
    which is a deliberate act rather than something an upgrade does behind the operator.

    A key this version has no field for is written back unchanged. Those keys come from a
    file some later version wrote, and dropping them would mean a downgrade that starts the
    proxy and lets one login through silently deletes settings the newer version needs. The
    store already learned that lesson from two implementations replacing each other's
    users: writing back a table you do not fully understand is how records disappear.

    Args:
        credential: The record to write

    Returns:
        The record's fields, keyed the way the file keys them
    """
    record: dict[str, object] = asdict(credential)
    del record["unknown_fields"]

    for name in _WIREGUARD_FIELDS:
        if record[name] is None:
            del record[name]

    record.update(credential.unknown_fields)
    return record


class AuthManager:
    """
    Manages authentication for the SOCKS5 proxy.

    Uses Argon2id for password hashing (recommended by OWASP)
    and provides secure credential storage.
    """

    # Argon2id parameters (OWASP recommended)
    ARGON2_TIME_COST = 3
    ARGON2_MEMORY_COST = 65536  # 64 MB
    ARGON2_PARALLELISM = 4

    def __init__(
        self,
        credentials_file: Optional[Path] = None,
        master_key: Optional[str] = None,
        salt_file: Optional[Path] = None,
        tunnel_network: Optional[str] = None,
    ):
        """
        Initialize the authentication manager.

        Args:
            credentials_file: Path to encrypted credentials file
            master_key: Master key for encrypting credentials at rest
            salt_file: Where the key-derivation salt lives, or None for the install's own
        """
        if credentials_file is None:
            from .paths import get_credentials_file

            self.credentials_file = get_credentials_file()
        else:
            self.credentials_file = credentials_file
        if tunnel_network is None:
            from .config import WireguardConfig

            tunnel_network = WireguardConfig().tunnel_network
        self._tunnel_network = parse_network(tunnel_network)
        self._salt_file = salt_file
        self._credentials: dict[str, Credential] = {}

        # Initialize password hasher with secure parameters
        self._hasher = PasswordHasher(
            time_cost=self.ARGON2_TIME_COST,
            memory_cost=self.ARGON2_MEMORY_COST,
            parallelism=self.ARGON2_PARALLELISM,
        )

        # Setup encryption for credentials at rest. Without a key this store would keep
        # password hashes and WireGuard private keys as plain JSON, in a file named
        # credentials.enc that says otherwise, and the operator would have no sign of it
        # until adding a key later made every one of those users unreadable.
        if master_key:
            self._fernet = self._derive_fernet_key(master_key)
        elif plaintext_credentials_allowed():
            self._fernet = None
        else:
            raise MissingMasterKey(_no_master_key_message(self.credentials_file))

        # Async save infrastructure. The lock on the credentials file covers the writes
        # themselves and is held for the whole of a change, so the scheduling state needs
        # a lock of its own or asking for a save would block behind the save it is asking
        # for.
        self._schedule_lock = threading.Lock()
        self._pending_save = False
        self._save_thread: Optional[threading.Thread] = None

        # Times of successful logins that have not reached disk yet. A write re-reads the
        # file first and that replaces every record in memory, so these are carried apart
        # from the table or they would be read straight back off it.
        self._pending_last_used: dict[str, str] = {}

        # Which version of the file the table in memory came from, for hot-reload
        self._last_version: Optional[_FileVersion] = None

        # Why the last read of the credentials file failed, or None when it read
        self.load_error: Optional[str] = None

        self._load_credentials()

        # Record which version was loaded
        self._last_version = _file_version(self.credentials_file)

    def _derive_fernet_key(self, master_key: str) -> Fernet:
        """Derive a Fernet key from the master key using PBKDF2."""
        # Use a fixed salt for key derivation (stored with config)
        salt_file = (
            self._salt_file
            if self._salt_file is not None
            else resolve_salt_file(self.credentials_file)
        )
        salt = read_or_create_salt(salt_file)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,  # OWASP recommended
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_key.encode()))
        return Fernet(key)

    def _load_credentials(self) -> bool:
        """
        Load credentials from the encrypted file.

        The file is parsed into a local table that replaces the live one only once it has
        been read in full, so an unreadable file leaves the users already in memory alone
        instead of emptying the table or killing the process that is starting up.

        A file that is confirmed absent is the other case entirely, and it empties the
        table. The two are told apart by asking for the bytes rather than by asking
        exists() first: only the read says which of the two happened, and it says so
        without the gap an exists() check leaves for the file to be deleted in.

        Returns:
            True if the credential table was replaced from disk, False otherwise
        """
        try:
            encrypted_data = self.credentials_file.read_bytes()

            if self._fernet:
                decrypted_data = self._fernet.decrypt(encrypted_data)
                data = json.loads(decrypted_data.decode())
            else:
                # Plain JSON, which only a store built under the plaintext opt-in has
                data = json.loads(encrypted_data.decode())

            loaded = {
                username: _checked_credential(username, cred_data, self._tunnel_network)
                for username, cred_data in data.items()
            }

        except FileNotFoundError:
            # No file is a table with nobody in it, on the path that serves logins as
            # well as the path that changes users. Keeping the old table let every user
            # an operator had deleted go on authenticating for as long as the process
            # ran, and let the next change write them all back to disk. An operator's rm
            # stopping logins is the lesser harm for a proxy whose whole job is deciding
            # who gets in.
            logger.error(
                "No credentials file, so nobody can authenticate",
                path=str(self.credentials_file),
                forgotten=len(self._credentials),
            )
            self._credentials = {}
            self.load_error = None
            return True

        except Exception as e:
            logger.error(
                "Failed to load credentials, keeping the credentials already in memory",
                path=str(self.credentials_file),
                count=len(self._credentials),
                error=str(e),
            )
            # Keeping the table is right for serving, but on a cold start that table is
            # empty and nothing else tells an empty store apart from a file that would
            # not decrypt. Recording why lets a caller see the difference, and it is what
            # stops the next write replacing a file this process never managed to read.
            # Left set until a load succeeds. InvalidToken, the failure this is most
            # likely to see, carries no message at all, so fall back to the type name
            # rather than recording an empty string that reads like no error.
            self.load_error = str(e) or type(e).__name__
            return False

        self._credentials = loaded
        self.load_error = None
        logger.info("Loaded credentials", count=len(self._credentials))

        # Said once per load rather than once per record, because every authentication
        # that notices the file has changed comes back through here. An operator seeing
        # this has a file written by a version newer than the one running, and the names
        # are what tells them which feature is going unenforced while it does.
        unknown = sorted({name for cred in loaded.values() for name in cred.unknown_fields})
        if unknown:
            logger.warning(
                "The credentials file holds settings this version does not know, so they "
                "are carried through untouched and nothing here enforces them",
                path=str(self.credentials_file),
                fields=unknown,
            )

        return True

    def reload_credentials(self) -> bool:
        """
        Reload credentials from file if it has been modified.

        This enables hot-reload of credentials when new users are added
        via CLI while the service is running.

        A file that has gone is a change like any other. Returning early on a missing file
        left the users from before the deletion in memory, and verify() is the only thing
        that ever calls this, so a deleted credentials file went on admitting its users
        indefinitely while a change made from the CLI emptied the table properly.

        Returns:
            True if credentials were reloaded, False if no changes detected
        """
        try:
            current_version = _file_version(self.credentials_file)
            # Different, not newer. A damaged file leaves its own version recorded below,
            # and restoring a backup with anything that keeps timestamps puts an older
            # one back, which "newer" would never look at again. The users would stay
            # missing until somebody restarted the process.
            if current_version != self._last_version:
                logger.info("Credentials file changed, reloading")
                reloaded = self._load_credentials()
                # advance past a file that could not be read too, or every single
                # authentication re-reads and re-logs the same bad bytes
                self._last_version = current_version
                return reloaded
        except Exception as e:
            logger.error("Failed to check/reload credentials", error=str(e))

        return False

    def _read_file_under_lock(self) -> None:
        """Re-read the file whatever its timestamp says.

        reload_credentials skips the read when the timestamp has not moved, and a
        filesystem that records whole seconds reports no movement for a write that landed
        in the same second as the last one. That is exactly the window a change has to be
        safe in, so this one always reads.
        """
        self._load_credentials()
        self._last_version = _file_version(self.credentials_file)

    @contextmanager
    def _mutating(self) -> Iterator[None]:
        """Hold the credentials file for a change, from re-reading it to replacing it.

        Every writer of this file, here and in the other process, is inside this for the
        whole of its change. The file is re-read on the way in so the change is applied to
        what is on disk right now, rather than to a table read before the other process
        wrote: taking the lock and then writing the older table loses the same users as
        taking no lock at all.

        The table goes back to what it was if the body raises, so a change that could not
        be written does not stay behind in memory looking as though it had been.
        """
        with lock_file(self.credentials_file):
            self._read_file_under_lock()
            self._apply_pending_last_used()
            snapshot = {name: replace(cred) for name, cred in self._credentials.items()}
            try:
                yield
            except BaseException:
                self._credentials = snapshot
                raise

    def _stamp_last_used(self, username: str) -> Optional[str]:
        """Record that a user has just authenticated.

        Two logins running at once each read the clock before either of them writes, so
        the one that read first can arrive second and put its earlier time back over the
        later one. A user's last-seen time then goes backwards, and the next save carries
        that backwards move to disk. What is kept is the latest of the three times in
        play: this login's, whatever is still waiting to be written, and what the record
        already says. Choosing between them happens under the same lock that stores the
        result, so nothing can be read and then overwritten.

        Returns:
            The time now on the record, or None if there is no such user in the table
        """
        cred = self._credentials.get(username)
        if cred is None:
            return None

        stamp = _utc_now_text()
        with self._schedule_lock:
            # text order is time order here: _utc_now_text writes no offset
            latest = max(stamp, self._pending_last_used.get(username, ""), cred.last_used or "")
            self._pending_last_used[username] = latest
            cred.last_used = latest
        return latest

    def _apply_pending_last_used(self) -> None:
        """Put the times that have not been written yet back onto the freshly read table.

        A later time already on disk wins, because it came from a login this process never
        saw. They are compared as text, which for an ISO timestamp is the order of time.

        Held for the whole walk rather than just for the snapshot, because a login landing
        partway through would otherwise read a record this is about to replace and write
        its own answer over the newer one.
        """
        with self._schedule_lock:
            for username, stamp in self._pending_last_used.items():
                cred = self._credentials.get(username)
                if cred is not None and (cred.last_used or "") < stamp:
                    cred.last_used = stamp

    def _forget_written_last_used(self, written: dict[str, dict]) -> None:
        """Drop the times the write just carried to disk.

        Compared against what was serialized rather than against the table, because a
        login recorded after the bytes were built is not in them. Those stay pending, and
        the save that login asked for still has something to write.

        Args:
            written: The records as they went to the file, keyed by username
        """
        with self._schedule_lock:
            for username, stamp in list(self._pending_last_used.items()):
                record = written.get(username)
                if record is None or record.get("last_used") == stamp:
                    del self._pending_last_used[username]

    def _save_credentials(self) -> None:
        """Save credentials to encrypted file (blocking).

        Meant to be reached from inside _mutating(), which is what makes the table this
        writes the one that was read from the file moments earlier under the same lock.
        The lock is taken here too, so the write is covered on its own as well; it is
        re-entrant, so being inside a change already costs nothing.

        Refuses while the file is present but unreadable. The table in memory was never
        read from it in that state, so writing replaces users this process cannot see:
        on a cold start after a lost salt or a regenerated master key the operator gets
        "no users", generates one, and the one-user table replaces the real ciphertext
        atomically with nothing left to decrypt later.
        """
        if self.load_error is not None:
            raise RuntimeError(
                f"Refusing to write {self.credentials_file}: the file exists but could "
                f"not be read ({self.load_error}), so saving would replace the users it "
                f"holds with what is in memory"
            )

        with lock_file(self.credentials_file):
            # take the table in one step before serializing: asdict() runs Python code,
            # so iterating the live dict lets another thread add or remove a user midway
            snapshot = list(self._credentials.items())
            data = {username: _record_for_file(cred) for username, cred in snapshot}
            json_data = json.dumps(data, indent=2)

            if self._fernet:
                payload = self._fernet.encrypt(json_data.encode())
            else:
                payload = json_data.encode()

            write_file_safely(self.credentials_file, payload)

            # the file we just wrote is not an external change; without this the next
            # verify() reloads our own output and races the write that produced it
            self._last_version = _file_version(self.credentials_file)
            self._forget_written_last_used(data)
            logger.info("Saved credentials", count=len(self._credentials))

    def _save_credentials_async(self) -> None:
        """Schedule credentials save in background thread (non-blocking).

        This method returns immediately and saves credentials in a background
        thread to avoid blocking connection handling. A request made while a save
        is already running is picked up by that save before it exits, so the last
        state always reaches disk.
        """
        with self._schedule_lock:
            self._pending_save = True

            if self._save_thread is not None:
                return

            self._save_thread = threading.Thread(target=self._drain_saves, daemon=True)
            self._save_thread.start()

    def _drain_saves(self) -> None:
        """Write credentials until no further save has been requested."""
        while True:
            with self._schedule_lock:
                if not self._pending_save:
                    # the writer gives the role back inside the same lock the scheduler
                    # takes to claim it, so a request cannot land in the gap between
                    # deciding to stop and stopping
                    self._save_thread = None
                    return
                self._pending_save = False

            try:
                with self._mutating():
                    self._save_credentials()
            except Exception as e:
                logger.error("Failed to save credentials in background", error=str(e))
                with self._schedule_lock:
                    self._save_thread = None
                return

    def flush_credentials(self) -> None:
        """Ensure all pending credential saves are completed.

        Call this during graceful shutdown to ensure no data is lost. Not to be called
        from inside a change: it waits for the writer, and the writer needs the lock the
        change is holding.
        """
        with self._schedule_lock:
            thread = self._save_thread

        if thread is not None and thread.is_alive():
            thread.join(timeout=5.0)

        with self._schedule_lock:
            pending = self._pending_save or bool(self._pending_last_used)
            self._pending_save = False

        if pending:
            with self._mutating():
                self._save_credentials()

    def add_user(
        self,
        username: str,
        password: str,
        use_tor: bool = True,
        bridge_type: str = "none",
        security_level: str = "basic",
        allowed_ports: Optional[list[int]] = None,
        rate_limit: Optional[int] = None,
        bind_port: Optional[int] = None,
        logging_enabled: bool = True,
    ) -> bool:
        """
        Add a new user with the given credentials.

        Args:
            username: The username (must be unique)
            password: The plaintext password (will be hashed)
            use_tor: Whether to route this user's traffic through Tor
            bridge_type: Tor bridge type (none, obfs4, snowflake)
            security_level: Security level (none, basic, moderate, paranoid)
            allowed_ports: List of allowed destination ports (None = all)
            rate_limit: Max requests per minute (None = server default)
            bind_port: Custom port for this user (None = shared server port)
            logging_enabled: Whether to log activity for this user (privacy setting)

        Returns:
            True if user was added, False if username exists
        """
        if not self._validate_username(username):
            raise ValueError("Invalid username format")

        if not self._validate_password(password):
            raise ValueError("Password does not meet security requirements")

        if security_level not in _SECURITY_LEVELS:
            raise ValueError("Invalid security level. Must be: none, basic, moderate, paranoid")

        if bridge_type not in _BRIDGE_TYPES:
            raise ValueError("Invalid bridge type. Must be: none, obfs4, snowflake")

        if bind_port is not None and (bind_port < 1 or bind_port > 65535):
            raise ValueError("Invalid bind port. Must be 1-65535")

        # Whether the name is taken is decided by add_credential, under the lock, against
        # the file as it is then. Deciding it here read a table loaded before another
        # process removed the user, and refused to let her be created again until some
        # unrelated reload happened to notice she had gone.

        # hashed before the file is locked: argon2 runs for hundreds of milliseconds and
        # holding the file for that long is the window this lock exists to close
        password_hash = self.hash_password(password)

        return self.add_credential(
            Credential(
                username=username,
                password_hash=password_hash,
                created_at=_utc_now_text(),
                use_tor=use_tor,
                bridge_type=bridge_type,
                security_level=security_level,
                allowed_ports=allowed_ports,
                rate_limit=rate_limit,
                bind_port=bind_port,
                logging_enabled=logging_enabled,
            )
        )

    def add_credential(self, credential: Credential) -> bool:
        """
        Add a user from a record whose password is already hashed.

        The API side builds its record before it reaches the store, so it needs a way in
        that does not hash a password it does not have.

        Args:
            credential: The record to store

        Returns:
            True if the user was added, False if the username is already taken
        """
        with self._mutating():
            if credential.username in self._credentials:
                logger.warning("User already exists", username=credential.username)
                return False

            _checked_credential(
                credential.username,
                _record_for_file(credential),
                self._tunnel_network,
            )
            self._credentials[credential.username] = credential
            self._save_credentials()

        logger.info("Added new user", username=credential.username)
        return True

    def remove_user(self, username: str) -> bool:
        """Remove a user from the system."""
        with self._mutating():
            if username not in self._credentials:
                return False

            del self._credentials[username]
            self._save_credentials()

        logger.info("Removed user", username=username)
        return True

    def get_credential(self, username: str) -> Optional[Credential]:
        """Get one stored record, or None if there is no such user."""
        return self._credentials.get(username)

    def list_credentials(self) -> list[Credential]:
        """Get every stored record."""
        return list(self._credentials.values())

    def update_credential(self, username: str, changes: dict[str, object]) -> Optional[Credential]:
        """
        Change named fields on one user's record.

        Args:
            username: The user to change
            changes: Field names mapped to their new values. A name the record does not
                have is ignored.

        Returns:
            The stored record, or None if there is no such user

        Raises:
            ValueError: when the completed record is not one the loader would accept
        """
        with self._mutating():
            cred = self._credentials.get(username)
            if cred is None:
                return None

            for name, value in changes.items():
                if name in _CREDENTIAL_FIELDS:
                    setattr(cred, name, value)

            # Checked before the write rather than after, because the load refuses a
            # record it cannot use and refusing is what sets load_error, which stops every
            # later write. Raising here leaves _mutating to put the table back.
            _checked_credential(
                username,
                _record_for_file(cred),
                self._tunnel_network,
            )

            self._save_credentials()

        return cred

    def update_last_used(self, username: str) -> bool:
        """
        Record a successful authentication and write it out before returning.

        Blocking, unlike the stamp verify() leaves behind, because the caller is a request
        that has nothing else to do until the change is on disk.

        Returns:
            True if the time was recorded, False if there is no such user
        """
        with self._mutating():
            if self._stamp_last_used(username) is None:
                return False
            self._save_credentials()
        return True

    def hash_password(self, password: str) -> str:
        """Hash a password with this store's Argon2id parameters."""
        return self._hasher.hash(password)

    def check_needs_rehash(self, password_hash: str) -> bool:
        """Report whether a stored hash was made with parameters this store has moved on from."""
        return self._hasher.check_needs_rehash(password_hash)

    def verify(self, username: str, password: str) -> bool:
        """
        Verify username and password combination.

        Uses constant-time comparison to prevent timing attacks.
        Automatically reloads credentials if the file has been modified
        (enables hot-reload when users are added via CLI).

        Args:
            username: The username to verify
            password: The plaintext password to verify

        Returns:
            True if credentials are valid, False otherwise
        """
        # Check for credential file updates (hot-reload for new users)
        self.reload_credentials()

        if username not in self._credentials:
            # Perform dummy hash to prevent timing attacks
            self.hash_password(_DUMMY_PASSWORD)
            logger.warning("Authentication failed: unknown user", username=username)
            return False

        cred = self._credentials[username]

        if not cred.enabled:
            # a disabled account has to cost what an unknown one costs, or the reply
            # comes back fast enough to tell an attacker the account is real
            self.hash_password(_DUMMY_PASSWORD)
            # Respect logging preference even for failed auth
            if getattr(cred, "logging_enabled", True):
                logger.warning("Authentication failed: user disabled", username=username)
            return False

        try:
            self._hasher.verify(cred.password_hash, password)
        except VerifyMismatchError:
            # Respect logging preference for failed auth attempts
            if getattr(cred, "logging_enabled", True):
                logger.warning("Authentication failed: wrong password", username=username)
            return False
        except InvalidHash:
            logger.error("Invalid hash format in credentials", username=username)
            return False

        # A rehash and a last_used stamp are both worth less than the users a write
        # would drop while the file will not read, and this credential verifies from
        # memory either way, so authentication is not made to depend on the write.
        if self.load_error is None:
            self._record_login(username, cred.password_hash, password)

        # Only log if user allows logging
        if getattr(cred, "logging_enabled", True):
            logger.info("Authentication successful", username=username)
        return True

    def _record_login(self, username: str, password_hash: str, password: str) -> None:
        """Write down what a successful login changes: the time, and a rehash if one is due.

        The new hash is computed before the file is locked. Holding the file for the length
        of an argon2 hash is the wait every other writer would be sitting through, and it
        is the window this lock exists to close.

        A write that cannot be done is logged and dropped. The password has already been
        checked against a hash that came out of the file, so failing the login because a
        timestamp would not go back in would shut everybody out of a proxy whose
        credentials file is busy.
        """
        rehash = self.hash_password(password) if self.check_needs_rehash(password_hash) else None

        try:
            if rehash is None:
                self._stamp_last_used(username)
                self._save_credentials_async()
                return

            with self._mutating():
                # the reload has replaced every record, so the one to change is whatever
                # is in the table now rather than the object verify() read
                stored = self._credentials.get(username)
                if stored is None:
                    return
                if stored.password_hash == password_hash:
                    stored.password_hash = rehash
                else:
                    # the password changed while this login was verifying, so the rehash
                    # is of a password that is no longer the user's. Writing it would put
                    # the old password back and silently stop the new one working. The
                    # login itself still stands: it did check a hash that was current.
                    logger.info(
                        "Skipped a rehash because the password changed first",
                        username=username,
                    )
                self._stamp_last_used(username)
                self._save_credentials()  # blocking save for a security-critical update
        except Exception as e:
            logger.error("Could not record a successful login", username=username, error=str(e))

    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        """Change a user's password."""
        if not self.verify(username, old_password):
            return False

        # the hash the old password was just checked against. It is what authorizes this
        # change, and it is read after verify() so a rehash verify() wrote is included
        authorized = self._credentials.get(username)
        if authorized is None:
            return False
        authorized_hash = authorized.password_hash

        if not self._validate_password(new_password):
            raise ValueError("New password does not meet security requirements")

        new_hash = self.hash_password(new_password)

        with self._mutating():
            cred = self._credentials.get(username)
            if cred is None:
                return False

            if cred.password_hash != authorized_hash:
                # somebody else changed the password between the check and here, so the
                # old password no longer authorizes anything. Overwriting now would undo
                # their change on the strength of a password that has been replaced.
                logger.warning(
                    "Password change refused: the password had already been changed",
                    username=username,
                )
                return False

            cred.password_hash = new_hash
            self._save_credentials()

        logger.info("Password changed", username=username)
        return True

    def generate_credentials(self) -> tuple[str, str]:
        """
        Generate secure random credentials.

        Returns:
            Tuple of (username, password)
        """
        username = f"user_{secrets.token_hex(8)}"
        # Generate password that meets all requirements
        password = self._generate_secure_password()
        return username, password

    def _generate_secure_password(self, length: int = 24) -> str:
        """
        Generate a password that meets security requirements.

        Includes a random word for memorability plus random characters.
        Ensures: uppercase, lowercase, digit, and special character.
        """
        import string

        # Word list for memorability
        words = [
            "tiger",
            "ocean",
            "maple",
            "river",
            "storm",
            "eagle",
            "frost",
            "blaze",
            "coral",
            "drift",
            "ember",
            "grove",
            "haven",
            "lunar",
            "nexus",
            "oasis",
            "prism",
            "quartz",
            "ridge",
            "solar",
            "thorn",
            "umbra",
            "vivid",
            "whirl",
            "zenith",
            "amber",
            "brisk",
            "cedar",
            "delta",
            "flint",
            "glade",
            "hydra",
            "ivory",
            "joker",
            "karma",
            "lotus",
            "mirth",
            "noble",
            "onyx",
            "pulse",
            "quest",
            "raven",
            "shade",
            "tempo",
            "ultra",
            "valor",
            "wrath",
            "xylon",
            "yield",
        ]

        # Character sets
        uppercase = string.ascii_uppercase
        lowercase = string.ascii_lowercase
        digits = string.digits
        special = "!@#$%^&*()-_=+"

        # Pick a random word and randomly capitalize first letter
        word = secrets.choice(words)
        if secrets.randbelow(2):
            word = word.capitalize()

        # Ensure at least one of each required type
        password_chars = [
            secrets.choice(uppercase),
            secrets.choice(lowercase),
            secrets.choice(digits),
            secrets.choice(special),
        ]

        # Calculate remaining length after word and required chars
        remaining = length - len(word) - 4

        # Fill remaining with random mix
        all_chars = uppercase + lowercase + digits + special
        for _ in range(remaining):
            password_chars.append(secrets.choice(all_chars))

        # Shuffle the non-word characters
        secrets.SystemRandom().shuffle(password_chars)

        # Insert word at a random position
        insert_pos = secrets.randbelow(len(password_chars) + 1)
        password_chars.insert(insert_pos, word)

        return "".join(password_chars)

    def get_user_tor_preference(self, username: str) -> Optional[bool]:
        """
        Get whether a user should have traffic routed through Tor.

        Args:
            username: The username to check

        Returns:
            True if Tor routing enabled, False if direct, None if user not found
        """
        if username not in self._credentials:
            return None
        return self._credentials[username].use_tor

    def set_user_tor_preference(self, username: str, use_tor: bool) -> bool:
        """
        Set whether a user should have traffic routed through Tor.

        Args:
            username: The username to update
            use_tor: Whether to enable Tor routing

        Returns:
            True if updated, False if user not found
        """
        if self.update_credential(username, {"use_tor": use_tor}) is None:
            return False

        logger.info("Updated Tor preference", username=username, use_tor=use_tor)
        return True

    def list_users(self) -> list[str]:
        """List all registered usernames."""
        return list(self._credentials.keys())

    def get_user_info(self, username: str) -> Optional[dict]:
        """
        Get all information about a user.

        Args:
            username: The username to look up

        Returns:
            Dictionary with user info, or None if user not found
        """
        if username not in self._credentials:
            return None

        cred = self._credentials[username]
        return {
            "username": cred.username,
            "created_at": cred.created_at,
            "last_used": cred.last_used,
            "enabled": cred.enabled,
            "use_tor": cred.use_tor,
            "bridge_type": getattr(cred, "bridge_type", "none"),
            "security_level": getattr(cred, "security_level", "basic"),
            "allowed_ports": getattr(cred, "allowed_ports", None),
            "rate_limit": getattr(cred, "rate_limit", None),
            "bind_port": getattr(cred, "bind_port", None),
            "logging_enabled": getattr(cred, "logging_enabled", True),
        }

    def set_user_enabled(self, username: str, enabled: bool) -> bool:
        """
        Enable or disable a user.

        Args:
            username: The username to update
            enabled: Whether the user should be enabled

        Returns:
            True if updated, False if user not found
        """
        if self.update_credential(username, {"enabled": enabled}) is None:
            return False

        logger.info("Updated user enabled status", username=username, enabled=enabled)
        return True

    def get_user_enabled(self, username: str) -> Optional[bool]:
        """
        Check if a user is enabled.

        Args:
            username: The username to check

        Returns:
            True if enabled, False if disabled, None if user not found
        """
        if username not in self._credentials:
            return None
        return self._credentials[username].enabled

    def get_user_security_level(self, username: str) -> Optional[str]:
        """
        Get a user's security level.

        Args:
            username: The username to check

        Returns:
            Security level string, or None if user not found
        """
        if username not in self._credentials:
            return None
        return getattr(self._credentials[username], "security_level", "basic")

    def set_user_security_level(self, username: str, level: str) -> bool:
        """
        Set a user's security level.

        Args:
            username: The username to update
            level: Security level (none, basic, moderate, paranoid)

        Returns:
            True if updated, False if user not found
        """
        if level not in ("none", "basic", "moderate", "paranoid"):
            raise ValueError("Invalid security level")

        if self.update_credential(username, {"security_level": level}) is None:
            return False

        logger.info("Updated security level", username=username, level=level)
        return True

    def get_user_allowed_ports(self, username: str) -> Optional[list[int]]:
        """
        Get a user's allowed ports.

        Args:
            username: The username to check

        Returns:
            List of allowed ports, None for all ports, or None if user not found
        """
        if username not in self._credentials:
            return None
        return getattr(self._credentials[username], "allowed_ports", None)

    def set_user_allowed_ports(self, username: str, ports: Optional[list[int]]) -> bool:
        """
        Set a user's allowed ports.

        Args:
            username: The username to update
            ports: List of allowed ports, or None for all ports

        Returns:
            True if updated, False if user not found
        """
        if self.update_credential(username, {"allowed_ports": ports}) is None:
            return False

        logger.info("Updated allowed ports", username=username, ports=ports)
        return True

    def get_user_rate_limit(self, username: str) -> Optional[int]:
        """
        Get a user's rate limit.

        Args:
            username: The username to check

        Returns:
            Rate limit (requests/min), None for server default, or None if user not found
        """
        if username not in self._credentials:
            return None
        return getattr(self._credentials[username], "rate_limit", None)

    def set_user_rate_limit(self, username: str, rate_limit: Optional[int]) -> bool:
        """
        Set a user's rate limit.

        Args:
            username: The username to update
            rate_limit: Max requests per minute, or None for server default

        Returns:
            True if updated, False if user not found
        """
        if self.update_credential(username, {"rate_limit": rate_limit}) is None:
            return False

        logger.info("Updated rate limit", username=username, rate_limit=rate_limit)
        return True

    def get_user_bridge_type(self, username: str) -> Optional[str]:
        """
        Get a user's bridge type.

        Args:
            username: The username to check

        Returns:
            Bridge type string, or None if user not found
        """
        if username not in self._credentials:
            return None
        return getattr(self._credentials[username], "bridge_type", "none")

    def set_user_bridge_type(self, username: str, bridge_type: str) -> bool:
        """
        Set a user's bridge type.

        Args:
            username: The username to update
            bridge_type: Bridge type (none, obfs4, snowflake)

        Returns:
            True if updated, False if user not found
        """
        if bridge_type not in ("none", "obfs4", "snowflake"):
            raise ValueError("Invalid bridge type")

        if self.update_credential(username, {"bridge_type": bridge_type}) is None:
            return False

        logger.info("Updated bridge type", username=username, bridge_type=bridge_type)
        return True

    def set_user_bind_port(self, username: str, bind_port: Optional[int]) -> bool:
        """
        Set a user's custom bind port.

        Args:
            username: The username to update
            bind_port: Custom port (1-65535), or None for shared server port

        Returns:
            True if updated, False if user not found
        """
        if bind_port is not None and (bind_port < 1 or bind_port > 65535):
            raise ValueError("Invalid bind port. Must be 1-65535")

        if self.update_credential(username, {"bind_port": bind_port}) is None:
            return False

        logger.info("Updated bind port", username=username, bind_port=bind_port)
        return True

    def get_user_logging_enabled(self, username: str) -> Optional[bool]:
        """
        Check if logging is enabled for a user.

        Args:
            username: The username to check

        Returns:
            True if logging enabled, False if disabled, None if user not found
        """
        if username not in self._credentials:
            return None
        return getattr(self._credentials[username], "logging_enabled", True)

    def set_user_logging_enabled(self, username: str, enabled: bool) -> bool:
        """
        Enable or disable logging for a user.

        When logging is disabled, no activity data (IPs, connections, targets)
        will be recorded for this user - a server-side privacy guarantee.

        Args:
            username: The username to update
            enabled: Whether logging should be enabled for this user

        Returns:
            True if updated, False if user not found
        """
        if self.update_credential(username, {"logging_enabled": enabled}) is None:
            return False

        # Only log this change if logging is being enabled (respect the setting)
        if enabled:
            logger.info("Updated logging status", username=username, logging_enabled=enabled)
        return True

    def get_users_with_custom_ports(self) -> dict[str, int]:
        """
        Get all users that have custom bind ports configured.

        Returns:
            Dictionary mapping username to bind port
        """
        ports: dict[str, int] = {}
        for username, cred in self._credentials.items():
            # read into a local and test that: the comprehension this replaces filtered on
            # a separate getattr call, so nothing tied the value it kept to the value it
            # had tested and the ports it returned were int | None against a signature
            # promising int
            bind_port = cred.bind_port
            if bind_port is not None:
                ports[username] = bind_port
        return ports

    @staticmethod
    def _validate_username(username: str) -> bool:
        """Validate username format."""
        if not username or len(username) < 3 or len(username) > 64:
            return False
        # Allow alphanumeric, underscore, hyphen
        return all(c.isalnum() or c in "_-" for c in username)

    @staticmethod
    def _validate_password(password: str) -> bool:
        """
        Validate password meets security requirements.

        Requirements:
        - Minimum 12 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        - At least one special character
        """
        if len(password) < 12:
            return False

        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)

        return has_upper and has_lower and has_digit and has_special
