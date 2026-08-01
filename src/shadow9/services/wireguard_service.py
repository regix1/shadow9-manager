"""
Hub-side WireGuard state: join tokens, the hub key, and the peer topology.

Two processes need the same answers here. The CLI runs `wg init` and `wg device add`, and
the API answers an enrolling node, and if they disagreed about which address is free or
which token has been spent the tunnel would break in a way nothing reports. So the state
lives in files both of them read, and every change is made under the interprocess lock.

The join token is `<id>.<secret>.<hub-public-key>`. The node sends the id and a signed
request, but never sends the secret. The hub stores the derived signing key, checks every
request field, and signs every response field together with the request nonce. The node
also keeps the cheap hub-public-key comparison and writes nothing when either check fails.

The token file therefore holds keys that can mint a join. Anyone who can read it can also
read the hub private key beside it, which is why that trade is accepted. Each enrolled node
also gets a refresh key derived from its join MAC key, and the topology counter advances
when the settings a node must pull change.
"""

import hashlib
import hmac
import ipaddress
import os
import secrets
from collections.abc import Sequence
from dataclasses import dataclass, fields, replace
from datetime import datetime, timedelta, timezone
from json import JSONDecodeError, dumps, loads
from operator import attrgetter
from pathlib import Path
from typing import Optional

from ..auth import AuthManager, Credential
from ..config import Config
from ..paths import get_config_dir, lock_file, write_file_safely
from ..wireguard import (
    AddressClaim,
    Peer,
    PeerRole,
    Topology,
    TunnelAddress,
    TunnelNetwork,
    claim_address,
    check_peer_routes,
    config_path,
    derive_public_key,
    is_valid_key,
    parse_address,
    parse_network,
    render_hub_config,
    render_spoke_config,
    spoke_allowed_ips,
    write_config,
)

# The hub's own name. It is not a stored user: its public key comes from the hub private
# key and its address is the first usable address in the tunnel network, so there is
# nothing about it left to keep in the credential file.
HUB_PEER_NAME = "hub"

# A join token is copied by hand from one terminal to another, so it has to live long
# enough for that and no longer.
DEFAULT_TOKEN_HOURS = 24

# The response version is a major number. A client can ignore added optional fields within
# this version, but must refuse a number whose meaning it does not know.
ENROLLMENT_PROTOCOL = 1
JOIN_MAC_MESSAGE = b"shadow9-join-mac-v1"
REFRESH_MAC_MESSAGE = b"shadow9-refresh-v1"
INVALID_REFRESH_KEY = "00" * hashlib.sha256().digest_size

# The credential fields a peer record needs. Named here so a store that does not carry
# them fails with a sentence rather than writing peers that silently vanish.
PEER_CREDENTIAL_FIELDS = (
    "wg_public_key",
    "wg_address",
    "wg_routes",
    "wg_role",
    "wg_endpoint",
    "wg_keepalive",
    "wg_private_key",
    "wg_refresh_key",
    "wg_full_tunnel",
    "wg_obfuscated",
)

# AmneziaWG's client-side junk parameters. Measured to work against a stock WireGuard hub,
# which reads the junk as an invalid packet, drops it, and completes the handshake anyway.
# Jmax stays well under the interface MTU: a junk packet the kernel has to fragment is more
# distinctive than no junk at all, which is the opposite of the point.
OBFUSCATION_JUNK_COUNT = 6
OBFUSCATION_JUNK_MIN = 64
OBFUSCATION_JUNK_MAX = 1200

# The architectures the node client is cross-compiled for, named the way Go names them.
# A router reports a different name for the same hardware: x86_64 is amd64, aarch64 is
# arm64, mipsel is mipsle. This is an allowlist and not a hint: the value arrives in a URL
# and is never joined onto a path, so an architecture that is not one of these is a 404
# rather than a filename somebody else chose.
NODE_ARCHITECTURES = ("amd64", "arm64", "mipsle")

# What `make -C node dist` writes, and what `make -C node checksums` records beside it
NODE_BINARY_PREFIX = "shadow9-node-linux-"
NODE_CHECKSUM_FILE = "SHA256SUMS"

# Said wherever the node binary is offered. The download has no server authentication of
# its own, exactly as enrollment does not, and the answer is the same one: a value the
# operator carries out of band. For enrollment that is the hub key inside the join token;
# here it is the checksum printed on the hub's own terminal.
BINARY_DOWNLOAD_NOTICE = (
    "Nothing authenticates that download. It is plain HTTP, so anyone on the path between "
    "the router and this hub can serve a different binary. The comparison above is what "
    "catches that, and it only means anything because you are reading these checksums here "
    "rather than fetching them over the same connection. Skip it and you are trusting every "
    "network in between with a file the router is about to run as root."
)

# Said by every command, because enrollment crosses plain HTTP.
CLEARTEXT_API_NOTICE = (
    "Enrollment uses plain HTTP. The token secret is not sent and the exchange is signed, "
    "but anyone on the path can still stop a join from completing. That denial of service "
    "is accepted."
)


class TokenRejected(ValueError):
    """Raised when a join token cannot be accepted. The message says why."""


class RefreshRejected(ValueError):
    """Raised when a refresh request is not authorized."""


class PeerFieldsMissing(RuntimeError):
    """Raised when the credential store has no room for peer fields."""

    def __init__(self, missing: Sequence[str]) -> None:
        super().__init__(
            "This credential store cannot hold WireGuard peers: it has no "
            f"{', '.join(missing)} field. Upgrade shadow9 before enrolling peers, because "
            "writing them now would drop them without an error."
        )
        self.missing = tuple(missing)


@dataclass(frozen=True)
class JoinToken:
    """One issued join key, as it is kept on disk.

    Attributes:
        id: The public lookup value sent by a joining node
        mac_key: The secret-derived HMAC key, hex encoded
        created_at: When the token was issued, ISO-8601 with an offset
        expires_at: When the token stops being accepted
        used_at: When the token was spent, or None while it is still good
        used_by: The peer that spent it, or None
    """

    id: str
    mac_key: str
    created_at: str
    expires_at: str
    used_at: Optional[str] = None
    used_by: Optional[str] = None

    def to_record(self) -> dict[str, object]:
        """
        Turn this token into the shape written to the token file.

        Returns:
            A JSON-serialisable record
        """
        return {
            "id": self.id,
            "mac_key": self.mac_key,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "used_at": self.used_at,
            "used_by": self.used_by,
        }

    @classmethod
    def from_record(cls, record: dict[str, object]) -> "JoinToken":
        """
        Read one token back out of the token file.

        Args:
            record: One entry from the file

        Returns:
            The token

        Raises:
            ValueError: If a required field is missing or is not text
        """
        token_id = record.get("id")
        mac_key = record.get("mac_key")
        created_at = record.get("created_at")
        expires_at = record.get("expires_at")
        used_at = record.get("used_at")
        used_by = record.get("used_by")

        if not isinstance(token_id, str) or not isinstance(mac_key, str):
            raise ValueError("A join token record is missing its id or MAC key")
        try:
            decoded_key = bytes.fromhex(mac_key)
        except ValueError as error:
            raise ValueError("A join token record has an unreadable MAC key") from error
        if len(decoded_key) != hashlib.sha256().digest_size:
            raise ValueError("A join token record has a MAC key of the wrong length")
        if not isinstance(created_at, str):
            raise ValueError("A join token record is missing its creation time")
        if not isinstance(expires_at, str):
            raise ValueError("A join token record is missing its expiry")

        return cls(
            id=token_id,
            mac_key=mac_key,
            created_at=created_at,
            expires_at=expires_at,
            used_at=used_at if isinstance(used_at, str) else None,
            used_by=used_by if isinstance(used_by, str) else None,
        )


@dataclass(frozen=True, repr=False)
class StoredConfig:
    """What a config already on disk tells us about the peer it belongs to.

    Older device records kept their private key only in the config file. Reading it here
    keeps those records rebuildable until the next device write moves the key into the
    encrypted credential store.

    Attributes:
        path: The config file
        private_key: The peer's base64 private key, read out of the file
        full_tunnel: Whether the peer routes everything through the hub
        obfuscated: Whether the config carries the AmneziaWG junk parameters
    """

    path: Path
    private_key: str
    full_tunnel: bool
    obfuscated: bool

    def __repr__(self) -> str:
        return (
            f"StoredConfig(path={self.path!r}, private_key='<hidden>', "
            f"full_tunnel={self.full_tunnel!r}, obfuscated={self.obfuscated!r})"
        )


@dataclass(frozen=True)
class Enrollment:
    """A node that has just joined.

    Attributes:
        peer: The peer as it was stored, including the address it was given
        topology: The star with that peer in it
        token: The record whose key signs this answer
    """

    peer: Peer
    topology: Topology
    token: JoinToken


@dataclass(frozen=True)
class Refresh:
    """The signed settings a node is allowed to refresh."""

    peer: Peer
    topology: Topology
    refresh_key: str
    allowed_ips: tuple[str, ...]
    revision: int


@dataclass(frozen=True)
class WireGuardState:
    """The hub-wide topology counter and the topology it counts."""

    revision: int = 0
    topology: str = ""


@dataclass(frozen=True)
class RenderedConfigs:
    """The result of reissuing configs after the topology changed.

    Attributes:
        written: Every config file rewritten
        unmanaged: Peers whose config this hub does not hold, so the operator has to
            reach them another way. Every node is one of these: a node generates its own
            key and the hub has never seen it
    """

    written: tuple[Path, ...]
    unmanaged: tuple[str, ...]


def utc_now() -> datetime:
    """
    The current time, with an offset attached.

    Returns:
        An aware datetime in UTC
    """
    return datetime.now(timezone.utc)


def hub_key_path() -> Path:
    """
    Where the hub's private key is kept.

    Returns:
        config/wireguard/hub.key under the install root
    """
    return get_config_dir() / "wireguard" / "hub.key"


def join_token_path() -> Path:
    """
    Where issued join tokens are kept.

    Returns:
        config/wireguard/join-tokens.json under the install root
    """
    return get_config_dir() / "wireguard" / "join-tokens.json"


def wireguard_state_path() -> Path:
    """Where the hub-wide topology revision is kept."""
    return get_config_dir() / "wireguard" / "state.json"


def save_hub_private_key(private_key: str) -> Path:
    """
    Write the hub's private key at 0600 inside a 0700 directory.

    Args:
        private_key: The base64 private key

    Returns:
        The file it was written to

    Raises:
        OSError: If the write fails, leaving any existing key untouched
    """
    path = hub_key_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(path.parent, 0o700)

    write_file_safely(path, (private_key + "\n").encode("utf-8"), mode=0o600)
    return path


def load_hub_private_key() -> Optional[str]:
    """
    Read the hub's private key back.

    Returns:
        The base64 private key, or None if this host has no hub key yet
    """
    path = hub_key_path()
    if not path.exists():
        return None

    text = path.read_text(encoding="utf-8").strip()
    return text or None


def hub_public_key() -> Optional[str]:
    """
    The hub's public key, derived from its private key rather than stored twice.

    Returns:
        The base64 public key, or None if this host has no hub key yet
    """
    private_key = load_hub_private_key()
    if private_key is None:
        return None
    return derive_public_key(private_key)


def hub_address(network: TunnelNetwork) -> TunnelAddress:
    """
    The address the hub always takes.

    Fixing it at the bottom of the range means it never has to be stored and never moves,
    and every peer config that names the hub keeps naming the same address.

    Args:
        network: The tunnel network

    Returns:
        The first usable address in the network

    Raises:
        ValueError: If the network has no usable address at all
    """
    for candidate in network.hosts():
        return candidate
    raise ValueError(
        f"Tunnel network {network} has no usable address, so it cannot hold a hub. "
        f"Pick a range with room for the hub and its peers."
    )


def create_join_token(
    public_key: str,
    lifetime_hours: int = DEFAULT_TOKEN_HOURS,
    path: Optional[Path] = None,
) -> str:
    """
    Issue a join token and record its derived MAC key.

    Args:
        public_key: The hub's base64 public key, which becomes the token's third part
        lifetime_hours: How long the secret stays good
        path: The token file, or None for the install's own

    Returns:
        The whole token, `<id>.<secret>.<hub-public-key>`. This is the only time the
        secret exists in readable form; only its derived MAC key is stored

    Raises:
        ValueError: If the lifetime is not positive
        OSError: If the token file cannot be written
    """
    if lifetime_hours <= 0:
        raise ValueError(f"A join token has to last some time, not {lifetime_hours} hours")

    store = path or join_token_path()
    token_id = secrets.token_urlsafe(32)
    secret = secrets.token_urlsafe(32)
    issued = utc_now()
    token = JoinToken(
        id=token_id,
        mac_key=join_mac_key(secret),
        created_at=issued.isoformat(),
        expires_at=(issued + timedelta(hours=lifetime_hours)).isoformat(),
    )

    with lock_file(store):
        tokens = _read_tokens(store)
        tokens.append(token)
        _write_tokens(store, tokens)

    return f"{token_id}.{secret}.{public_key}"


def split_join_token(token: str) -> tuple[str, str, str]:
    """
    Take a join token apart into its id, secret and the hub key it names.

    Args:
        token: The whole token as the operator pasted it

    Returns:
        The id, secret and the hub's base64 public key

    Raises:
        TokenRejected: If the token is not three parts separated by dots, or the last
            part is not a WireGuard key
    """
    parts = token.strip().split(".")
    if len(parts) != 3 or not all(parts):
        raise TokenRejected(
            "That does not look like a join token. A join token is an id, a secret, and "
            "the hub's public key separated by dots, and 'shadow9 wg init' prints the "
            "whole command to run."
        )
    token_id, secret, key = parts

    if not is_valid_key(key):
        raise TokenRejected(
            "The last part of this join token is not a WireGuard public key. That part "
            "is what proves which hub answered, so the token cannot be used without it."
        )

    return token_id, secret, key


def join_mac_key(secret: str) -> str:
    """Derive the key used to sign one token's enrollment exchange."""
    return hmac.new(secret.encode("utf-8"), JOIN_MAC_MESSAGE, hashlib.sha256).hexdigest()


def refresh_key(mac_key: str) -> str:
    """Derive a node's durable refresh key from its join MAC key."""
    return hmac.new(bytes.fromhex(mac_key), REFRESH_MAC_MESSAGE, hashlib.sha256).hexdigest()


def request_mac(
    mac_key: str,
    token_id: str,
    name: str,
    public_key: str,
    routes: Sequence[str],
    nonce: str,
) -> str:
    """Sign the exact request text shared with the node client."""
    message = (
        "shadow9-join-request-v1\n"
        f"token_id={token_id}\n"
        f"name={name}\n"
        f"public_key={public_key}\n"
        f"routes={','.join(routes)}\n"
        f"nonce={nonce}\n"
    ).encode("utf-8")
    return hmac.new(bytes.fromhex(mac_key), message, hashlib.sha256).hexdigest()


def response_mac(
    mac_key: str,
    nonce: str,
    address: str,
    hub_public_key: str,
    hub_endpoint: str,
    tunnel_network: str,
    mtu: int,
    keepalive: int,
    protocol: int,
) -> str:
    """Sign the exact response text shared with the node client."""
    message = (
        "shadow9-join-response-v1\n"
        f"nonce={nonce}\n"
        f"address={address}\n"
        f"hub_public_key={hub_public_key}\n"
        f"hub_endpoint={hub_endpoint}\n"
        f"tunnel_network={tunnel_network}\n"
        f"mtu={mtu}\n"
        f"keepalive={keepalive}\n"
        f"protocol={protocol}\n"
    ).encode("utf-8")
    return hmac.new(bytes.fromhex(mac_key), message, hashlib.sha256).hexdigest()


def refresh_request_mac(key: str, name: str, nonce: str) -> str:
    """Sign the exact refresh request text shared with the node client."""
    message = ("shadow9-refresh-request-v1\n" f"name={name}\n" f"nonce={nonce}\n").encode("utf-8")
    return hmac.new(bytes.fromhex(key), message, hashlib.sha256).hexdigest()


def refresh_response_mac(
    key: str,
    nonce: str,
    address: str,
    hub_public_key: str,
    hub_endpoint: str,
    tunnel_network: str,
    allowed_ips: Sequence[str],
    mtu: int,
    keepalive: int,
    protocol: int,
    revision: int,
) -> str:
    """Sign the exact refresh response text shared with the node client."""
    message = (
        "shadow9-refresh-response-v1\n"
        f"nonce={nonce}\n"
        f"address={address}\n"
        f"hub_public_key={hub_public_key}\n"
        f"hub_endpoint={hub_endpoint}\n"
        f"tunnel_network={tunnel_network}\n"
        f"allowed_ips={','.join(allowed_ips)}\n"
        f"mtu={mtu}\n"
        f"keepalive={keepalive}\n"
        f"protocol={protocol}\n"
        f"revision={revision}\n"
    ).encode("utf-8")
    return hmac.new(bytes.fromhex(key), message, hashlib.sha256).hexdigest()


def consume_join_token(
    token_id: str,
    peer_name: str,
    path: Optional[Path] = None,
) -> JoinToken:
    """
    Spend a join token, refusing one that is unknown, expired or already spent.

    Args:
        token_id: The public id the joining peer sent
        peer_name: The peer spending it, recorded against the token
        path: The token file, or None for the install's own

    Returns:
        The spent token

    Raises:
        TokenRejected: If the token is unknown, expired or already used
    """
    store = path or join_token_path()

    with lock_file(store):
        tokens = _read_tokens(store)
        match = _checked_join_token(token_id, tokens)

        spent = replace(match, used_at=utc_now().isoformat(), used_by=peer_name)
        _write_tokens(
            store,
            [spent if hmac.compare_digest(e.id, match.id) else e for e in tokens],
        )

    return spent


def check_join_token(
    token_id: str,
    path: Optional[Path] = None,
    used_by: Optional[str] = None,
) -> JoinToken:
    """Check a token without spending it, optionally accepting its prior user."""
    store = path or join_token_path()
    with lock_file(store):
        return _checked_join_token(token_id, _read_tokens(store), used_by=used_by)


def check_join_request(
    token_id: str,
    name: str,
    public_key: str,
    routes: Sequence[str],
    nonce: str,
    mac: str,
    path: Optional[Path] = None,
    used_by: Optional[str] = None,
) -> JoinToken:
    """Find the token and refuse a request whose signed fields changed."""
    token = check_join_token(token_id, path=path, used_by=used_by)
    expected = request_mac(token.mac_key, token_id, name, public_key, routes, nonce)
    if not hmac.compare_digest(mac, expected):
        raise TokenRejected("This enrollment request has an invalid MAC.")
    return token


def _checked_join_token(
    token_id: str,
    tokens: Sequence[JoinToken],
    used_by: Optional[str] = None,
) -> JoinToken:
    """Return the matching usable token from an already-read token list."""
    match = next((entry for entry in tokens if hmac.compare_digest(entry.id, token_id)), None)
    if match is None:
        raise TokenRejected(
            "This join token is not one this hub issued. Run 'shadow9 wg token' on the "
            "hub for a token this hub will accept."
        )

    if match.used_at is not None and match.used_by != used_by:
        raise TokenRejected(
            f"This join token was already used at {match.used_at}"
            f"{f' by {match.used_by}' if match.used_by else ''}. A join token is good "
            f"for one peer, so ask the hub operator for a new one."
        )

    if match.used_at is not None and match.used_by == used_by:
        return match

    if _expiry_passed(match.expires_at):
        raise TokenRejected(
            f"This join token expired at {match.expires_at}. Ask the hub operator for a new one."
        )
    return match


def _restore_join_token(token: JoinToken, path: Optional[Path] = None) -> None:
    """Put one token record back without replacing tokens issued meanwhile."""
    store = path or join_token_path()
    with lock_file(store):
        tokens = _read_tokens(store)
        restored = [token if hmac.compare_digest(entry.id, token.id) else entry for entry in tokens]
        _write_tokens(store, restored)


def list_join_tokens(path: Optional[Path] = None) -> list[JoinToken]:
    """
    Every token this hub has issued, spent or not.

    Args:
        path: The token file, or None for the install's own

    Returns:
        The tokens, oldest first
    """
    return _read_tokens(path or join_token_path())


def require_peer_fields(credential_type: type = Credential) -> None:
    """
    Refuse to write peers into a store that has nowhere to put them.

    `update_credential` drops a field the record does not have, and `Credential(**record)`
    would refuse the whole record, so without this check a peer written against an older
    store disappears with nothing reported.

    Args:
        credential_type: The stored record type, injectable so a test can prove the check
            fires

    Raises:
        PeerFieldsMissing: If any peer field is absent
    """
    stored = {field.name for field in fields(credential_type)}
    missing = [name for name in PEER_CREDENTIAL_FIELDS if name not in stored]
    if missing:
        raise PeerFieldsMissing(missing)


def peer_from_credential(credential: Credential) -> Optional[Peer]:
    """
    Build a peer out of a stored user record.

    Args:
        credential: One stored record

    Returns:
        The peer, or None if this user is not a WireGuard peer

    Raises:
        ValueError: If the record carries peer fields that do not parse
    """
    public_key = getattr(credential, "wg_public_key", None)
    address = getattr(credential, "wg_address", None)
    if not public_key or not address:
        return None

    routes = getattr(credential, "wg_routes", None) or []
    role = getattr(credential, "wg_role", None) or PeerRole.NODE.value
    keepalive = getattr(credential, "wg_keepalive", None)

    return Peer(
        name=credential.username,
        public_key=public_key,
        address=parse_address(address),
        role=PeerRole(role),
        routes=tuple(parse_network(route) for route in routes),
        endpoint=getattr(credential, "wg_endpoint", None) or None,
        keepalive=keepalive,
        enabled=credential.enabled,
    )


def peer_changes(
    peer: Peer,
    private_key: Optional[str] = None,
    full_tunnel: Optional[bool] = None,
    obfuscated: Optional[bool] = None,
    refresh_key: Optional[str] = None,
) -> dict[str, object]:
    """
    The stored fields that describe this peer.

    Args:
        peer: The peer being saved

    Returns:
        Field names mapped to the values to store
    """
    return {
        "wg_public_key": peer.public_key,
        "wg_address": str(peer.address),
        "wg_routes": [str(route) for route in peer.routes],
        "wg_role": peer.role.value,
        "wg_endpoint": peer.endpoint,
        "wg_keepalive": peer.keepalive,
        "wg_private_key": private_key,
        "wg_refresh_key": refresh_key,
        "wg_full_tunnel": full_tunnel,
        "wg_obfuscated": obfuscated,
    }


def cleared_peer_changes() -> dict[str, object]:
    """
    The stored fields that say this user is no longer a peer.

    Returns:
        Field names mapped to empty values
    """
    return {
        "wg_public_key": None,
        "wg_address": None,
        "wg_routes": None,
        "wg_role": None,
        "wg_endpoint": None,
        "wg_keepalive": None,
        "wg_private_key": None,
        "wg_refresh_key": None,
        "wg_full_tunnel": None,
        "wg_obfuscated": None,
    }


def save_peer(
    auth_manager: AuthManager,
    peer: Peer,
    private_key: Optional[str] = None,
    full_tunnel: Optional[bool] = None,
    obfuscated: Optional[bool] = None,
    refresh_key: Optional[str] = None,
) -> Credential:
    """
    Store a peer, creating the user record when there is not one already.

    A peer's lifecycle is a user's lifecycle, which is why the fields live here and not in
    a second file. A peer that has no user yet gets one with a random password nobody is
    told, because a phone on the tunnel is not a proxy login; `shadow9 user modify` sets a
    real password if that user should have one.

    Args:
        auth_manager: The credential store
        peer: The peer to store

    Returns:
        The stored record

    Raises:
        PeerFieldsMissing: If the store cannot hold peer fields
        ValueError: If the record could not be created
    """
    require_peer_fields()

    existing = auth_manager.get_credential(peer.name)
    if existing is not None:
        updated = auth_manager.update_credential(
            peer.name,
            peer_changes(peer, private_key, full_tunnel, obfuscated, refresh_key),
        )
        if updated is None:
            raise ValueError(f"User '{peer.name}' went away while its peer was being saved")
        return updated

    _, password = auth_manager.generate_credentials()
    credential = Credential(
        username=peer.name,
        password_hash=auth_manager.hash_password(password),
        created_at=utc_now().replace(tzinfo=None).isoformat(),
        wg_public_key=peer.public_key,
        wg_address=str(peer.address),
        wg_routes=[str(route) for route in peer.routes],
        wg_role=peer.role.value,
        wg_endpoint=peer.endpoint,
        wg_keepalive=peer.keepalive,
        wg_private_key=private_key,
        wg_refresh_key=refresh_key,
        wg_full_tunnel=full_tunnel,
        wg_obfuscated=obfuscated,
    )
    if not auth_manager.add_credential(credential):
        raise ValueError(f"User '{peer.name}' already exists")

    return credential


def clear_peer(auth_manager: AuthManager, name: str) -> bool:
    """
    Take the peer fields off a user, leaving the user alone.

    Args:
        auth_manager: The credential store
        name: The peer to clear

    Returns:
        True if a record was changed, False if there is no such user
    """
    return auth_manager.update_credential(name, cleared_peer_changes()) is not None


def load_topology(
    cfg: Config,
    credentials: Sequence[Credential],
    public_key: str,
    masquerade_interface: Optional[str] = None,
) -> Topology:
    """
    Build the whole star out of the config file and the credential store.

    Args:
        cfg: The loaded configuration
        credentials: Every stored user record
        public_key: The hub's base64 public key
        masquerade_interface: The hub's internet-facing interface, needed only when some
            peer uses a full tunnel

    Returns:
        The topology every renderer takes

    Raises:
        ValueError: If the tunnel network or a stored peer field does not parse
    """
    network = parse_network(cfg.wireguard.tunnel_network)
    hub = Peer(
        name=HUB_PEER_NAME,
        public_key=public_key,
        address=hub_address(network),
        role=PeerRole.HUB,
        endpoint=cfg.wireguard.hub_endpoint or None,
        keepalive=None,
    )

    spokes: list[Peer] = []
    for credential in credentials:
        peer = peer_from_credential(credential)
        if peer is not None and peer.role is not PeerRole.HUB:
            spokes.append(peer)

    return Topology(
        tunnel_network=network,
        hub=hub,
        spokes=tuple(spokes),
        listen_port=cfg.wireguard.listen_port,
        mtu=cfg.wireguard.mtu,
        dns=", ".join(cfg.wireguard.dns) if cfg.wireguard.dns else None,
        interface=cfg.wireguard.interface,
        masquerade_interface=masquerade_interface,
    )


def _topology_text(topology: Topology) -> str:
    """Return a stable digest input for changes that alter peer routing."""
    peers = sorted(topology.spokes, key=attrgetter("name"))
    record = {
        "tunnel_network": str(topology.tunnel_network),
        "hub_public_key": topology.hub.public_key,
        "hub_endpoint": topology.hub.endpoint,
        "peers": [
            {
                "name": peer.name,
                "public_key": peer.public_key,
                "address": str(peer.address),
                "routes": [str(route) for route in peer.routes],
                "enabled": peer.enabled,
            }
            for peer in peers
        ],
    }
    encoded = dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _read_wireguard_state(path: Path) -> WireGuardState:
    """Read the hub-wide topology counter, starting at zero on an older install."""
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return WireGuardState()
    except OSError as error:
        raise OSError(f"Could not read WireGuard state file {path}: {error}") from error

    try:
        record = loads(raw)
    except (JSONDecodeError, UnicodeDecodeError) as error:
        raise OSError(f"WireGuard state file {path} is not valid JSON: {error}") from error
    if not isinstance(record, dict):
        raise OSError(f"WireGuard state file {path} does not contain an object")
    revision = record.get("revision")
    topology = record.get("topology")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        raise OSError(f"WireGuard state file {path} has an invalid revision")
    if not isinstance(topology, str):
        raise OSError(f"WireGuard state file {path} has an invalid topology digest")
    return WireGuardState(revision=revision, topology=topology)


def topology_revision(topology: Topology, path: Optional[Path] = None) -> int:
    """Return the revision for this topology, bumping it once when the topology changed."""
    state_path = path or wireguard_state_path()
    current_topology = _topology_text(topology)
    with lock_file(state_path):
        state = _read_wireguard_state(state_path)
        if hmac.compare_digest(state.topology, current_topology):
            return state.revision
        changed = WireGuardState(revision=state.revision + 1, topology=current_topology)
        state_path.parent.mkdir(parents=True, exist_ok=True)
        write_file_safely(
            state_path,
            (dumps({"revision": changed.revision, "topology": changed.topology}) + "\n").encode(
                "utf-8"
            ),
            mode=0o600,
        )
        return changed.revision


def address_claims(topology: Topology) -> list[AddressClaim]:
    """
    Every tunnel address currently spoken for, including disabled peers.

    A disabled peer keeps its address, so handing it to somebody else would move it the
    moment the first peer is enabled again, and WireGuard reports nothing when it does.

    Args:
        topology: The star

    Returns:
        One claim per peer, hub included
    """
    claims = [AddressClaim(address=topology.hub.address, peer=topology.hub.name)]
    claims.extend(AddressClaim(address=peer.address, peer=peer.name) for peer in topology.spokes)
    return claims


def config_setting(text: str, key: str) -> Optional[str]:
    """
    Read one `Key = value` line out of a config file.

    Args:
        text: The whole config
        key: The setting name, matched without regard to case

    Returns:
        The value with its surrounding space removed, or None if the key is not there
    """
    wanted = key.strip().lower()
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        name, separator, value = stripped.partition("=")
        if separator and name.strip().lower() == wanted:
            return value.strip()
    return None


def read_stored_config(path: Path) -> Optional[StoredConfig]:
    """
    Read a config the hub wrote earlier, so it can be reissued.

    Args:
        path: The config file

    Returns:
        What the file says about its peer, or None if there is no file or no key in it
    """
    if not path.exists():
        return None

    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None

    private_key = config_setting(text, "PrivateKey")
    if not private_key:
        return None

    allowed = config_setting(text, "AllowedIPs") or ""
    return StoredConfig(
        path=path,
        private_key=private_key,
        full_tunnel="0.0.0.0/0" in allowed,
        obfuscated=config_setting(text, "Jc") is not None,
    )


def masquerade_interface_from_config(text: str) -> Optional[str]:
    """
    Recover the hub's outward interface from a hub config it wrote earlier.

    The interface is not a setting on its own; it appears only in the MASQUERADE rule.
    Reading it back is what lets the hub config be reissued without the operator passing
    the flag again every time a peer is added.

    Args:
        text: The hub config

    Returns:
        The interface name, or None if the config does not NAT anything out
    """
    for line in text.splitlines():
        if "MASQUERADE" not in line or " -o " not in line:
            continue
        parts = line.split()
        if "-o" in parts:
            index = parts.index("-o")
            if index + 1 < len(parts):
                return parts[index + 1]
    return None


def with_obfuscation(config_text: str, mtu: Optional[int]) -> str:
    """
    Add AmneziaWG's client-side junk parameters to a rendered spoke config.

    Only the client-side ones. `H1`-`H4` and `S1`-`S4` have to match on both ends and would
    lock every stock WireGuard client out of this hub, so they are deliberately not here.

    Args:
        config_text: The rendered config
        mtu: The interface MTU, used to keep junk packets under it

    Returns:
        The config with the junk parameters in its `[Interface]` section
    """
    ceiling = (mtu - 100) if mtu else OBFUSCATION_JUNK_MAX
    junk_max = max(OBFUSCATION_JUNK_MIN, min(OBFUSCATION_JUNK_MAX, ceiling))
    junk_min = min(OBFUSCATION_JUNK_MIN, junk_max)

    block = [
        "# AmneziaWG junk packets, sent before each handshake. Client side only: a stock",
        "# WireGuard hub reads them as invalid, drops them, and handshakes normally.",
        f"Jc = {OBFUSCATION_JUNK_COUNT}",
        f"Jmin = {junk_min}",
        f"Jmax = {junk_max}",
    ]

    lines = config_text.splitlines()
    for index, line in enumerate(lines):
        if line.strip() == "[Interface]":
            return "\n".join([*lines[: index + 1], *block, *lines[index + 1 :]]) + "\n"

    return config_text


def render_peer_config(
    topology: Topology,
    peer: Peer,
    private_key: str,
    full_tunnel: bool = False,
    obfuscate: bool = False,
) -> str:
    """
    Render one spoke's config, with the tunnel mode and obfuscation it asked for.

    A full-tunnel peer sends its name lookups through the hub as well, otherwise it keeps
    resolving on whatever network it is sitting on while everything else goes down the
    tunnel, which is the leak the tunnel was meant to close.

    Args:
        topology: The star
        peer: The spoke whose config is being built
        private_key: That spoke's base64 private key
        full_tunnel: Send all traffic through the hub
        obfuscate: Add the client-side junk parameters

    Returns:
        The config file text

    Raises:
        ValueError: If the hub has no endpoint
    """
    rendered_from = topology
    if full_tunnel and not topology.dns:
        rendered_from = replace(topology, dns=str(topology.hub.address))

    text = render_spoke_config(rendered_from, peer, private_key, full_tunnel=full_tunnel)
    if obfuscate:
        text = with_obfuscation(text, topology.mtu)
    return text


def regenerate_configs(
    topology: Topology,
    private_key: str,
    credentials: Sequence[Credential] = (),
) -> RenderedConfigs:
    """
    Reissue the hub config and every peer config this hub holds.

    Adding, removing or disabling any peer changes what every other peer routes into the
    tunnel, so this rewrites all of them rather than the one that changed. A node's config
    was written by the node and its private key never reached the hub, so a node is named
    in `unmanaged` instead: the operator has to tell it, which is what
    `shadow9 wg hub set-endpoint` prints.

    Args:
        topology: The star as it now is
        private_key: The hub's base64 private key

    Returns:
        What was rewritten and who could not be

    Raises:
        OSError: If a config could not be written
    """
    written: list[Path] = []
    unmanaged: list[str] = []
    records = {credential.username: credential for credential in credentials}

    hub_path = config_path(topology.interface)
    write_config(hub_path, render_hub_config(topology, private_key))
    written.append(hub_path)

    for peer in topology.spokes:
        stored = read_stored_config(config_path(peer.name))
        record = records.get(peer.name)
        device_key = getattr(record, "wg_private_key", None) if record is not None else None
        if device_key is None and stored is not None:
            device_key = stored.private_key
        if device_key is None or not topology.hub.endpoint:
            unmanaged.append(peer.name)
            continue

        full_tunnel = getattr(record, "wg_full_tunnel", None) if record is not None else None
        if full_tunnel is None:
            full_tunnel = stored.full_tunnel if stored is not None else False
        obfuscated = getattr(record, "wg_obfuscated", None) if record is not None else None
        if obfuscated is None:
            obfuscated = stored.obfuscated if stored is not None else False

        text = render_peer_config(
            topology,
            peer,
            device_key,
            full_tunnel=full_tunnel,
            obfuscate=obfuscated,
        )
        path = stored.path if stored is not None else config_path(peer.name)
        write_config(path, text)
        written.append(path)

    topology_revision(topology)
    return RenderedConfigs(written=tuple(written), unmanaged=tuple(unmanaged))


def _remember_configs(topology: Topology) -> dict[Path, Optional[bytes]]:
    """Read every config a regeneration can replace before the first write."""
    paths = {config_path(topology.interface)}
    paths.update(config_path(peer.name) for peer in topology.spokes)
    return {path: path.read_bytes() if path.exists() else None for path in paths}


def _restore_configs(copies: dict[Path, Optional[bytes]]) -> None:
    """Restore config bytes saved by `_remember_configs`."""
    for path, body in copies.items():
        if body is None:
            if path.exists():
                path.unlink()
        else:
            write_file_safely(path, body, mode=0o600)


def _restore_enrollment(
    auth_manager: AuthManager,
    name: str,
    previous: Optional[dict[str, object]],
    token: JoinToken,
    copies: dict[Path, Optional[bytes]],
) -> tuple[str, ...]:
    """Try every part of an enrollment rollback and return anything that failed."""
    errors: list[str] = []
    try:
        if previous is None:
            auth_manager.remove_user(name)
        else:
            auth_manager.update_credential(name, previous)
    except Exception as error:
        errors.append(f"peer record: {error}")

    try:
        _restore_join_token(token)
    except Exception as error:
        errors.append(f"join token: {error}")

    try:
        _restore_configs(copies)
    except Exception as error:
        errors.append(f"config files: {error}")
    return tuple(errors)


def enroll_peer(
    cfg: Config,
    auth_manager: AuthManager,
    token_id: str,
    name: str,
    public_key: str,
    routes: Sequence[str] = (),
    nonce: str = "",
    mac: str = "",
) -> Enrollment:
    """
    Take a node into the tunnel: spend its token, give it an address, store it, reissue.

    The whole of it runs under one lock. Two nodes enrolling at the same moment would
    otherwise read the same free address and both be told to take it, and WireGuard hands
    a duplicated address to whichever peer connects last with nothing logged anywhere.

    Args:
        cfg: The loaded configuration
        auth_manager: The credential store
        token_id: The public id from the join token
        name: The peer name the node asked for
        public_key: The node's base64 public key. The node keeps its private key; this hub
            never sees it
        routes: Subnets behind this node that every other peer should reach through it
        nonce: The fresh value this attempt signs and the response covers
        mac: The request signature

    Returns:
        The stored peer and the topology it now belongs to

    Raises:
        TokenRejected: If the token id is unknown, expired or spent, or the MAC is wrong
        ValueError: If the name, the key or a route does not parse, or the name is taken
            by a peer that is already enrolled
        PeerFieldsMissing: If the store cannot hold peer fields
        OSError: If a config could not be written
    """
    require_peer_fields()

    hub_private_key = load_hub_private_key()
    if hub_private_key is None:
        raise ValueError(
            "This host has no WireGuard hub. Run 'shadow9 wg init' before a node can join."
        )
    hub_key = derive_public_key(hub_private_key)

    if not is_valid_key(public_key):
        raise ValueError("The public key sent is not a WireGuard public key")

    checked_name = checked_peer_name(name)
    parsed_routes = tuple(parse_network(route) for route in routes)

    with lock_file(hub_key_path()):
        auth_manager.reload_credentials()
        checked_token = check_join_request(
            token_id,
            name,
            public_key,
            routes,
            nonce,
            mac,
            used_by=checked_name,
        )
        existing = auth_manager.get_credential(checked_name)
        previous = (
            None
            if existing is None
            else {field: getattr(existing, field) for field in PEER_CREDENTIAL_FIELDS}
        )
        existing_peer = peer_from_credential(existing) if existing is not None else None

        if existing_peer is not None:
            if checked_token.used_at is not None and existing_peer.public_key == public_key:
                outward = None
                hub_config = config_path(cfg.wireguard.interface)
                if hub_config.exists():
                    outward = masquerade_interface_from_config(
                        hub_config.read_text(encoding="utf-8")
                    )
                topology = load_topology(cfg, auth_manager.list_credentials(), hub_key, outward)
                return Enrollment(peer=existing_peer, topology=topology, token=checked_token)
            raise ValueError(
                f"'{checked_name}' is already a peer on this hub. Remove it with "
                f"'shadow9 wg remove {checked_name}' or join under another name."
            )

        hub_config = config_path(cfg.wireguard.interface)
        outward = None
        if hub_config.exists():
            outward = masquerade_interface_from_config(hub_config.read_text(encoding="utf-8"))

        topology = load_topology(cfg, auth_manager.list_credentials(), hub_key, outward)
        claim = _claim_for(topology, checked_name)

        peer = Peer(
            name=checked_name,
            public_key=public_key,
            address=claim.address,
            role=PeerRole.NODE,
            routes=parsed_routes,
            keepalive=cfg.wireguard.keepalive or None,
        )
        check_peer_routes(topology, peer)
        topology = topology.with_peer(peer)
        copies = _remember_configs(topology)
        spent_token = consume_join_token(token_id, checked_name)

        try:
            save_peer(
                auth_manager,
                peer,
                refresh_key=refresh_key(spent_token.mac_key),
            )
            regenerate_configs(topology, hub_private_key, auth_manager.list_credentials())
        except Exception as error:
            failures = _restore_enrollment(
                auth_manager, checked_name, previous, checked_token, copies
            )
            if failures:
                raise OSError(
                    "Enrollment stopped after storage began, and the previous state could "
                    f"not be fully restored ({'; '.join(failures)}): {error}"
                ) from error
            raise OSError(
                "Enrollment failed, and the previous peer, token and configs were "
                f"restored: {error}"
            ) from error

    return Enrollment(peer=peer, topology=topology, token=spent_token)


def _current_topology(cfg: Config, auth_manager: AuthManager, public_key: str) -> Topology:
    """Build topology from credentials read while the caller holds the hub lock."""
    outward = None
    hub_config = config_path(cfg.wireguard.interface)
    if hub_config.exists():
        outward = masquerade_interface_from_config(hub_config.read_text(encoding="utf-8"))
    return load_topology(cfg, auth_manager.list_credentials(), public_key, outward)


def refresh_peer(
    cfg: Config,
    auth_manager: AuthManager,
    name: str,
    nonce: str,
    mac: str,
) -> Refresh:
    """Authenticate a node and return the complete settings it should now apply."""
    hub_private_key = load_hub_private_key()
    if hub_private_key is None:
        raise ValueError(
            "This host has no WireGuard hub. Run 'shadow9 wg init' before a node can refresh."
        )

    with lock_file(hub_key_path()):
        auth_manager.reload_credentials()
        credential = auth_manager.get_credential(name)
        peer = peer_from_credential(credential) if credential is not None else None
        key = getattr(credential, "wg_refresh_key", None) if credential is not None else None
        checked_key = key if isinstance(key, str) else INVALID_REFRESH_KEY
        expected = refresh_request_mac(checked_key, name, nonce)
        mac_matches = hmac.compare_digest(mac, expected)
        if peer is None or key is None or not mac_matches:
            raise RefreshRejected("This refresh request is not authorized.")

        topology = _current_topology(cfg, auth_manager, derive_public_key(hub_private_key))
        current_peer = topology.find_peer(peer.name)
        if current_peer is None:
            raise RefreshRejected("This refresh request is not authorized.")
        return Refresh(
            peer=current_peer,
            topology=topology,
            refresh_key=key,
            allowed_ips=spoke_allowed_ips(topology, current_peer),
            revision=topology_revision(topology),
        )


def set_peer_enabled(cfg: Config, auth_manager: AuthManager, name: str, enabled: bool) -> bool:
    """Change a user's enabled flag and reissue configs when that user is a peer."""
    with lock_file(hub_key_path()):
        auth_manager.reload_credentials()
        existing = auth_manager.get_credential(name)
        if existing is None:
            return False
        peer = peer_from_credential(existing)
        changed = auth_manager.update_credential(name, {"enabled": enabled})
        if changed is None:
            return False

        private_key = load_hub_private_key()
        if peer is not None and private_key is not None:
            topology = _current_topology(cfg, auth_manager, derive_public_key(private_key))
            regenerate_configs(topology, private_key, auth_manager.list_credentials())
        return True


def delete_user_peer(cfg: Config, auth_manager: AuthManager, name: str) -> bool:
    """Delete one user, reissue configs, and remove files that belonged to its peer."""
    with lock_file(hub_key_path()):
        auth_manager.reload_credentials()
        existing = auth_manager.get_credential(name)
        if existing is None:
            return False
        peer = peer_from_credential(existing)
        if not auth_manager.remove_user(name):
            return False

        private_key = load_hub_private_key()
        if peer is not None and private_key is not None:
            topology = _current_topology(cfg, auth_manager, derive_public_key(private_key))
            regenerate_configs(topology, private_key, auth_manager.list_credentials())

        if peer is not None:
            for path in (config_path(name), config_path(name).with_suffix(".svg")):
                if path.exists():
                    path.unlink()
        return True


def checked_peer_name(name: str) -> str:
    """
    Check a name is one this hub can store and can build a file name from.

    The name arrives over the network and becomes both a user name and a path, so it is
    checked here rather than trusted twice.

    Args:
        name: The requested peer name

    Returns:
        The name with its surrounding space removed

    Raises:
        ValueError: If the name is not 3 to 64 characters of letters, digits, underscore
            or hyphen
    """
    cleaned = name.strip()
    if len(cleaned) < 3 or len(cleaned) > 64:
        raise ValueError(f"Peer name '{cleaned}' has to be 3 to 64 characters long")
    if not all(character.isalnum() or character in "_-" for character in cleaned):
        raise ValueError(
            f"Peer name '{cleaned}' can only hold letters, digits, underscores and hyphens"
        )
    return cleaned


def checked_endpoint(endpoint: str) -> str:
    """
    Check an endpoint is a host and a port peers can dial.

    Args:
        endpoint: The `host:port` peers should use, or a bare host

    Returns:
        The endpoint, with the default port added when none was given

    Raises:
        ValueError: If there is no host, or the port is not a port
    """
    cleaned = endpoint.strip()
    if not cleaned:
        raise ValueError("An endpoint needs an address peers can reach")

    host, separator, port = cleaned.rpartition(":")
    if not separator:
        return f"{cleaned}:{_DEFAULT_ENDPOINT_PORT}"

    # An IPv6 literal is full of colons, so only a bracketed one carries a port
    if ":" in host and not host.endswith("]"):
        return f"[{cleaned}]:{_DEFAULT_ENDPOINT_PORT}"

    if not host:
        raise ValueError(f"Endpoint '{cleaned}' has a port but no address in front of it")

    try:
        number = int(port)
    except ValueError as error:
        raise ValueError(f"Endpoint '{cleaned}' does not end in a port number") from error

    if number < 1 or number > 65535:
        raise ValueError(f"Endpoint '{cleaned}' names port {number}, which is not a port")

    return cleaned


_DEFAULT_ENDPOINT_PORT = 51820


def _claim_for(topology: Topology, name: str) -> AddressClaim:
    """
    Give a peer the next free tunnel address.

    Args:
        topology: The star as it now is
        name: The peer being given an address

    Returns:
        The claim

    Raises:
        AddressTaken: If another peer holds the address
        NetworkFull: If the tunnel network has no free address
    """
    return claim_address(topology.tunnel_network, address_claims(topology), name)


def _expiry_passed(expires_at: str) -> bool:
    """
    Whether an expiry timestamp is in the past.

    An unreadable timestamp counts as expired. A token whose expiry cannot be read is a
    token nobody can say is still good, and refusing it costs one reissue.

    Args:
        expires_at: The stored expiry

    Returns:
        True if the token should no longer be accepted
    """
    try:
        deadline = datetime.fromisoformat(expires_at)
    except ValueError:
        return True

    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)
    return deadline <= utc_now()


def _read_tokens(path: Path) -> list[JoinToken]:
    """
    Read the token file, treating only a missing file as empty.

    Args:
        path: The token file

    Returns:
        Every token in it, oldest first
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    except OSError as error:
        raise OSError(f"Could not read join token file {path}: {error}") from error

    try:
        data = loads(text)
    except JSONDecodeError as error:
        raise OSError(f"Join token file {path} is not valid JSON: {error}") from error

    if not isinstance(data, dict):
        raise OSError(f"Join token file {path} does not hold an object")

    entries = data.get("tokens")
    if not isinstance(entries, list):
        raise OSError(f"Join token file {path} does not hold a token list")

    tokens: list[JoinToken] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise OSError(f"Join token file {path} holds a token that is not an object")
        try:
            tokens.append(JoinToken.from_record(entry))
        except ValueError as error:
            raise OSError(f"Join token file {path} holds an unreadable token: {error}") from error
    return tokens


def _write_tokens(path: Path, tokens: Sequence[JoinToken]) -> None:
    """
    Replace the token file.

    Args:
        path: The token file
        tokens: What it should hold

    Raises:
        OSError: If the write fails, leaving the old file in place
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(path.parent, 0o700)

    body = dumps({"tokens": [token.to_record() for token in tokens]}, indent=2)
    write_file_safely(path, (body + "\n").encode("utf-8"), mode=0o600)


def node_binary_dir() -> Path:
    """
    Where `make -C node dist` leaves the cross-compiled node client.

    Returns:
        node/dist under the install root
    """
    from ..paths import get_root

    return get_root() / "node" / "dist"


def node_binary_path(architecture: str) -> Optional[Path]:
    """
    The built node client for one architecture, if it was built.

    The architecture arrives in a URL, so it is matched against `NODE_ARCHITECTURES` and
    the file name is then built from that constant. Nothing the caller sent is ever joined
    onto a path, which is the only way this cannot be talked into serving another file.

    Args:
        architecture: The Go architecture name, for example `amd64`

    Returns:
        The binary, or None if the architecture is not one this project builds or the
        build has not been run
    """
    if architecture not in NODE_ARCHITECTURES:
        return None

    directory = node_binary_dir()
    path = directory / f"{NODE_BINARY_PREFIX}{architecture}"
    if not path.is_file():
        return None

    # A symlink left in the dist directory could still point outside it
    if directory.resolve() not in path.resolve().parents:
        return None

    return path


def node_checksum_path() -> Optional[Path]:
    """
    The recorded checksums of the built binaries, if they were recorded.

    Returns:
        The SHA256SUMS file, or None when `make -C node checksums` has not been run
    """
    path = node_binary_dir() / NODE_CHECKSUM_FILE
    return path if path.is_file() else None


def node_binary_checksums() -> dict[str, str]:
    """
    Read the recorded checksum of each built binary.

    The operator reads these off the hub's terminal and compares them on the router, which
    is what makes an unauthenticated download over plain HTTP checkable at all.

    Returns:
        Architecture names mapped to their SHA-256, empty when nothing was recorded
    """
    path = node_checksum_path()
    if path is None:
        return {}

    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}

    checksums: dict[str, str] = {}
    for line in text.splitlines():
        digest, _, name = line.strip().partition(" ")
        # sha256sum writes "<digest>  <name>" in text mode and "<digest> *<name>" in
        # binary mode, so the marker comes off before the name is read
        name = name.strip().lstrip("*")
        if not digest or not name.startswith(NODE_BINARY_PREFIX):
            continue
        architecture = name[len(NODE_BINARY_PREFIX) :]
        if architecture in NODE_ARCHITECTURES:
            checksums[architecture] = digest

    return checksums


def tunnel_network_of(cfg: Config) -> TunnelNetwork:
    """
    The configured tunnel network, parsed.

    Args:
        cfg: The loaded configuration

    Returns:
        The network peer addresses come from

    Raises:
        ValueError: If the configured value is not a network
    """
    return parse_network(cfg.wireguard.tunnel_network)


def is_public_endpoint_host(endpoint: str) -> bool:
    """
    Whether an endpoint names an address the internet can route to.

    A name is treated as public, because nothing here can resolve it and the operator who
    typed it is the one who knows where it points. Private ranges are the obvious failure,
    but so are the documentation ranges people copy out of examples, and `is_global`
    catches both where a private-address check would let 203.0.113.10 through.

    Args:
        endpoint: The `host:port` peers dial

    Returns:
        True when peers on the internet could reach the host, False when they could not
    """
    host = endpoint.rsplit(":", 1)[0].strip("[]")
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return True
