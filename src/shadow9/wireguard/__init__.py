"""
WireGuard star topology: keys, tunnel addresses and config rendering.

Nothing in here touches a live interface or needs root. It generates key material, decides
which peer holds which address, and produces config text, which is why the whole of it runs
and is tested on Windows as well as Linux.
"""

from .addresses import (
    AddressClaim,
    AddressTaken,
    NetworkFull,
    TunnelAddress,
    TunnelNetwork,
    claim_address,
    next_free_address,
    parse_address,
    parse_network,
    usable_address_count,
    usable_addresses,
)
from .keys import (
    KEY_BYTES,
    KEY_TEXT_LENGTH,
    Keypair,
    derive_public_key,
    generate_keypair,
    generate_private_key,
    is_valid_key,
)
from .render import (
    CONFIG_DIR_MODE,
    CONFIG_FILE_MODE,
    DEFAULT_INTERFACE,
    DEFAULT_KEEPALIVE_SECONDS,
    DEFAULT_LISTEN_PORT,
    DEFAULT_MTU,
    FULL_TUNNEL_ALLOWED_IPS,
    Peer,
    PeerRole,
    Topology,
    check_peer_routes,
    config_path,
    key_protection_notice,
    render_hub_config,
    render_spoke_config,
    spoke_allowed_ips,
    write_config,
)

__all__ = [
    "CONFIG_DIR_MODE",
    "CONFIG_FILE_MODE",
    "DEFAULT_INTERFACE",
    "DEFAULT_KEEPALIVE_SECONDS",
    "DEFAULT_LISTEN_PORT",
    "DEFAULT_MTU",
    "FULL_TUNNEL_ALLOWED_IPS",
    "KEY_BYTES",
    "KEY_TEXT_LENGTH",
    "AddressClaim",
    "AddressTaken",
    "Keypair",
    "NetworkFull",
    "Peer",
    "PeerRole",
    "Topology",
    "TunnelAddress",
    "TunnelNetwork",
    "claim_address",
    "check_peer_routes",
    "config_path",
    "derive_public_key",
    "generate_keypair",
    "generate_private_key",
    "is_valid_key",
    "key_protection_notice",
    "next_free_address",
    "parse_address",
    "parse_network",
    "render_hub_config",
    "render_spoke_config",
    "spoke_allowed_ips",
    "usable_address_count",
    "usable_addresses",
    "write_config",
]
