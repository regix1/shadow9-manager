"""
Server management endpoints.

RESTful API for server status and control.
"""

import asyncio

from fastapi import APIRouter, Depends

from ...core.config import api_worker_count, get_settings, Settings
from ...core.logging import get_logger
from ...memory_budget import MIB, read_memory_budget
from ...schemas.server import (
    AuthSection,
    LogSection,
    SecuritySection,
    ServerConfigResponse,
    ServerSection,
    ServerStatusResponse,
    TorSection,
    WireguardSection,
)
from ...services.user_service import UserService
from ..deps import get_current_admin, get_user_service


logger = get_logger(__name__)

router = APIRouter(prefix="/server", tags=["server"])

# a status probe must answer quickly even when the proxy host drops packets
PROXY_PROBE_TIMEOUT = 1.0


async def _something_is_listening(host: str, port: int) -> bool:
    """
    Check whether a TCP connection to the configured proxy address is accepted.

    This observes exactly one thing: that some process accepted a connection at that
    host and port. It does not prove the listener is the proxy, and it does not prove
    the proxy can serve anyone, since a proxy with an empty credential store accepts
    connections and then fails every authentication. The API runs in a different
    process, so this is as much as it can honestly establish.

    Args:
        host: The proxy's configured bind address
        port: The proxy's configured bind port

    Returns:
        True if a TCP connection was accepted, False otherwise
    """
    # a wildcard bind is not a connectable address, so probe the loopback it covers
    probe_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host

    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(probe_host, port), timeout=PROXY_PROBE_TIMEOUT
        )
    except (OSError, asyncio.TimeoutError) as e:
        logger.debug(
            "Proxy did not accept a probe connection", host=probe_host, port=port, error=str(e)
        )
        return False

    writer.close()
    try:
        # a status endpoint must answer even if the peer never finishes the close
        await asyncio.wait_for(writer.wait_closed(), timeout=PROXY_PROBE_TIMEOUT)
    except (OSError, asyncio.TimeoutError):
        pass
    return True


@router.get(
    "/status",
    response_model=ServerStatusResponse,
    summary="Get server status",
    responses={
        200: {"description": "Server status information"},
        401: {"description": "Invalid API key"},
    },
)
async def get_server_status(
    settings: Settings = Depends(get_settings),
    user_service: UserService = Depends(get_user_service),
    _admin: str = Depends(get_current_admin),
) -> ServerStatusResponse:
    """
    Get current server status and statistics.

    `running` reports whether something accepted a TCP connection at the configured
    proxy address. That is a real observation, but it is not a health check: it does
    not prove the listener is the proxy, nor that the proxy can authenticate anyone.

    The proxy runs in a different process, so its connection count and start time
    cannot be read from here. `uptime_seconds` is therefore always null, and
    `active_connections` is null whenever something is listening. When nothing is
    listening, `active_connections` is 0, which is the one case it is known.
    """
    total_users = await user_service.count()
    running = await _something_is_listening(settings.server.host, settings.server.port)

    return ServerStatusResponse(
        running=running,
        host=settings.server.host,
        port=settings.server.port,
        active_connections=None if running else 0,
        total_users=total_users,
        tor_enabled=settings.tor.enabled,
        uptime_seconds=None,
    )


@router.get(
    "/config",
    response_model=ServerConfigResponse,
    summary="Get server configuration",
    responses={
        200: {"description": "Server configuration"},
        401: {"description": "Invalid API key"},
    },
)
async def get_server_config(
    settings: Settings = Depends(get_settings), _admin: str = Depends(get_current_admin)
) -> ServerConfigResponse:
    """
    Get current server configuration (non-sensitive values).

    The memory figures are read fresh on each call rather than reported from startup,
    because a cgroup limit can be changed under a running process and the answer that
    matters is the one that applies now.
    """
    budget = read_memory_budget()

    return ServerConfigResponse(
        server=ServerSection(
            host=settings.server.host,
            port=settings.server.port,
            max_connections=settings.server.max_connections,
            connection_timeout=settings.server.connection_timeout,
        ),
        tor=TorSection(
            enabled=settings.tor.enabled,
            socks_port=settings.tor.socks_port,
        ),
        auth=AuthSection(
            require_auth=settings.auth.require_auth,
            max_failed_attempts=settings.auth.max_failed_attempts,
            lockout_duration_minutes=settings.auth.lockout_duration_minutes,
            # The configuration, which is null when nothing was set and each process
            # works its own number out. Reporting this process's figure here presented
            # the API's answer as though it were the proxy's, and they differ: the proxy
            # subtracts the relay buffers it holds and this process does not hold any,
            # so on a tight box it runs one hash where this one would allow two.
            max_concurrent_auth=(
                None if settings.auth.sized_from_memory else settings.auth.max_concurrent_auth
            ),
            # What this process will actually run, which is the only effective number it
            # can speak for. The proxy's is in its own startup log.
            max_concurrent_auth_api_process=settings.auth.max_concurrent_auth,
            # So the number and where it came from can be read off a running process
            # instead of grepped out of the startup log.
            max_concurrent_auth_sized_from_memory=settings.auth.sized_from_memory,
            api_workers=api_worker_count(),
            memory_budget_mib=budget.usable_bytes // MIB,
            memory_budget_source=budget.source,
            memory_budget_detail=budget.detail,
            # False when the figures are an assumption because the limit could not be
            # read, which is worth seeing next to the number it produced.
            memory_budget_measured=budget.measured,
        ),
        security=SecuritySection(
            allowed_ports=settings.security.allowed_ports,
            rate_limit_per_minute=settings.security.rate_limit_per_minute,
            block_private_ranges=settings.security.block_private_ranges,
            allow_localhost=settings.security.allow_localhost,
            blocked_hosts=settings.security.blocked_hosts,
        ),
        log=LogSection(
            level=settings.log.level,
            format=settings.log.format,
        ),
        wireguard=WireguardSection(
            enabled=settings.wireguard.enabled,
            listen_port=settings.wireguard.listen_port,
            enrollment_host=settings.wireguard.enrollment_host,
            enrollment_port=settings.wireguard.enrollment_port,
            tunnel_network=settings.wireguard.tunnel_network,
            hub_endpoint=settings.wireguard.hub_endpoint,
            mtu=settings.wireguard.mtu,
            dns=settings.wireguard.dns,
            keepalive=settings.wireguard.keepalive,
        ),
    )
