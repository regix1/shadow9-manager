"""
SOCKS5 Server Implementation with Authentication.

Implements RFC 1928 (SOCKS5) and RFC 1929 (Username/Password Authentication).
Security-focused implementation with proper input validation and error handling.
"""

import asyncio
import os
import socket
import struct
import threading
import time
from contextlib import suppress
from datetime import datetime
from enum import IntEnum
from dataclasses import dataclass
from typing import Optional, Callable, Awaitable
from ipaddress import ip_address, IPv4Address, IPv6Address

import structlog

from .auth import AuthManager
from .security import SecurityLevel, get_security_preset, DPIBypass
from .bridges import TorBridgeConnector, BridgeConfig, BridgeType
from .logging_utils import UserAwareLogger
from .memory_budget import (
    MIB,
    MIN_PERMITS,
    HashPermits,
    MemoryCeilingTooLow,
    choose_hash_permits,
    read_memory_budget,
)

logger = structlog.get_logger(__name__)


class Socks5AuthMethod(IntEnum):
    """SOCKS5 Authentication Methods (RFC 1928)."""

    NO_AUTH = 0x00
    GSSAPI = 0x01
    USERNAME_PASSWORD = 0x02
    NO_ACCEPTABLE = 0xFF


class Socks5Command(IntEnum):
    """SOCKS5 Commands (RFC 1928)."""

    CONNECT = 0x01
    BIND = 0x02
    UDP_ASSOCIATE = 0x03


class Socks5AddressType(IntEnum):
    """SOCKS5 Address Types (RFC 1928)."""

    IPV4 = 0x01
    DOMAIN = 0x03
    IPV6 = 0x04


class Socks5Reply(IntEnum):
    """SOCKS5 Reply Codes (RFC 1928)."""

    SUCCEEDED = 0x00
    GENERAL_FAILURE = 0x01
    NOT_ALLOWED = 0x02
    NETWORK_UNREACHABLE = 0x03
    HOST_UNREACHABLE = 0x04
    CONNECTION_REFUSED = 0x05
    TTL_EXPIRED = 0x06
    COMMAND_NOT_SUPPORTED = 0x07
    ADDRESS_TYPE_NOT_SUPPORTED = 0x08


class UpstreamProxyUnreachable(ConnectionError):
    """The upstream SOCKS5 proxy socket itself could not be opened.

    Distinct from a proxy that answers and then refuses the target: this one means
    nothing is listening, so a Tor instance started for a bridge type is gone.
    """


@dataclass
class LockoutState:
    """Failed logins counted for one (source address, username) pair."""

    failures: int = 0
    last_failure: float = 0.0


@dataclass
class RateLimitState:
    """Requests counted for one user inside the window that is currently open."""

    requests: int = 0
    window_start: float = 0.0


def _prune_tracking[K, V](
    tracked: dict[K, V],
    touched_at: Callable[[V], float],
    expiry_cutoff: float,
    max_entries: int,
) -> None:
    """Drop entries past their expiry, then the oldest survivors until one slot is free.

    Both maps this serves are keyed by values the client picks, a source address and a
    username, so without a ceiling a client cycling either one grows them for as long as
    the process runs. Expiry alone is not enough: a fast enough cycle outruns it.
    """
    for key in [key for key, value in tracked.items() if touched_at(value) < expiry_cutoff]:
        del tracked[key]

    while len(tracked) >= max_entries:
        oldest = min(tracked, key=lambda key: touched_at(tracked[key]))
        del tracked[oldest]


@dataclass
class ConnectionInfo:
    """Information about a proxied connection."""

    client_addr: tuple[str, int]
    target_addr: str
    target_port: int
    username: Optional[str] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    # User settings (populated from auth manager)
    use_tor: bool = True
    bridge_type: str = "none"
    security_level: str = "basic"


class Socks5Server:
    """
    Secure SOCKS5 proxy server with username/password authentication.

    Features:
    - RFC 1928/1929 compliant
    - Username/password authentication required
    - Connection rate limiting
    - Proper input validation
    - Async I/O for high performance
    """

    SOCKS_VERSION = 0x05
    AUTH_VERSION = 0x01
    MAX_BUFFER_SIZE = 65536
    CONNECTION_TIMEOUT = 30
    BRIDGE_CONNECTION_TIMEOUT = 120  # Longer timeout for Snowflake/bridge connections
    ONION_CONNECTION_TIMEOUT = 180  # Even longer for .onion (6-hop circuits)
    RELAY_TIMEOUT = 600  # 10 minutes for large transfers
    TLS_RECORD_TIMEOUT = 1.0

    # Connection tuning
    LISTEN_BACKLOG = 256  # TCP listen queue size

    # How often the memory ceiling is read again while the server runs. A limit can be
    # lowered under a live process with systemctl set-property, and the startup answer
    # then plans for memory the process no longer has. Reading four small files twice a
    # minute costs nothing next to being wrong about it for the life of the daemon.
    BUDGET_RECHECK_SECONDS = 30.0

    # How long one permit removal waits before it looks up to see whether the server is
    # still running. A permit is taken away by acquiring it and not giving it back, so the
    # wait is as long as the argon2 hash holding it; without a check in the middle, a
    # shutdown would sit behind every permit the resize still had to take. Long enough not
    # to be a spin, short enough that stop() is not held up by it.
    AUTH_RESIZE_POLL_SECONDS = 0.5

    # How often every blocked name is looked up again. The addresses behind a name move,
    # so an answer kept from hours ago blocks whoever holds that address now and misses
    # the one the name points at today. Five minutes is longer than the TTL most names
    # publish and short enough that a moved name is followed within one.
    BLOCKED_HOST_RECHECK_SECONDS = 300.0

    # How long one blocked name is given to answer. The round as a whole is bounded at
    # startup, but the watch that repeats it awaits it directly, so a resolver that
    # accepted the query and never replied used to hold the watch on that one name for
    # the life of the process: every later name in the list went un-refreshed, and any
    # that had never resolved stayed unblocked.
    BLOCKED_HOST_RESOLVE_TIMEOUT = 5.0

    # How many of those run at once. One at a time makes a long block list take the
    # length of the list to get through, and all at once is a burst at the resolver every
    # five minutes.
    BLOCKED_HOST_RESOLVE_CONCURRENCY = 8

    # How long a failed bridge start is remembered before another Tor spawn is attempted
    BRIDGE_FAILURE_TTL = 300

    # The window the per-minute request limit is counted over
    RATE_LIMIT_WINDOW = 60

    # Ceiling on each attacker-keyed tracking map. At 4096 entries the worst case is a
    # few megabytes per map, which is small next to one argon2 hash.
    MAX_TRACKED_ENTRIES = 4096

    # How many times one source address's budget the whole account is given before the
    # account-wide count refuses anybody. A source that spends its own budget locks
    # itself out, so reaching this takes a crowd of addresses rather than one caller.
    ACCOUNT_ATTEMPT_FACTOR = 10

    # How long a successful login keeps that address trusted for that account
    KNOWN_SOURCE_TTL = 86400

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 1080,
        auth_manager: Optional[AuthManager] = None,
        upstream_proxy: Optional[tuple[str, int]] = None,
        upstream_proxies: Optional[dict[str, tuple[str, int]]] = None,
        allowed_commands: Optional[set[Socks5Command]] = None,
        bridge_base_port: int = 9100,
        max_connections: int = 100,
        connection_timeout: int | None = None,
        relay_timeout: int | None = None,
        buffer_size: int | None = None,
        max_concurrent_auth: Optional[int] = None,
        block_private_ranges: bool = True,
        allow_localhost: bool = False,
        blocked_hosts: Optional[list[str]] = None,
        max_failed_attempts: int = 5,
        lockout_duration_minutes: float = 15,
        rate_limit_per_minute: int = 100,
    ):
        """
        Initialize the SOCKS5 server.

        Args:
            host: Host address to bind to
            port: Port to listen on
            auth_manager: Authentication manager for credentials
            upstream_proxy: Optional default upstream SOCKS5 proxy (host, port)
            upstream_proxies: Optional dict of bridge_type -> (host, port) for per-bridge proxies
            allowed_commands: Set of allowed SOCKS5 commands (default: CONNECT only)
            bridge_base_port: Base port for dynamically created Tor bridge instances
            max_connections: Maximum number of connections handled at the same time
            connection_timeout: Seconds allowed for handshakes, connections, and writes
            relay_timeout: Seconds a relay direction may wait for more input
            buffer_size: Bytes read and reserved per relay direction
            max_concurrent_auth: Maximum password verifications running at the same time,
                or None to size it from the memory this process is allowed to use
            block_private_ranges: Refuse destinations that are not on the public internet
            allow_localhost: Permit loopback destinations even when private ranges are blocked
            blocked_hosts: Host names the operator refuses, parent entries covering subdomains
            max_failed_attempts: Failed logins a source may spend on one username before lockout
            lockout_duration_minutes: How long a locked-out source and username stay refused
            rate_limit_per_minute: Requests a user may make per minute without a per-user limit
        """
        self.host = host
        self.port = port
        self.auth_manager = auth_manager
        self.upstream_proxy = upstream_proxy
        self.upstream_proxies = upstream_proxies or {}
        self.allowed_commands = allowed_commands or {Socks5Command.CONNECT}
        self._bridge_base_port = bridge_base_port
        self.max_connections = max_connections
        if connection_timeout is not None:
            self.CONNECTION_TIMEOUT = connection_timeout
        if relay_timeout is not None:
            self.RELAY_TIMEOUT = relay_timeout
        if buffer_size is not None:
            self.MAX_BUFFER_SIZE = buffer_size
        # The relay holds one buffer in each direction for every connection, and that
        # memory is not available to password hashing, so the two caps are sized against
        # one budget rather than each assuming it has the whole of it.
        self.hash_permits = choose_hash_permits(
            max_concurrent_auth,
            relay_reserve_bytes=max_connections * 2 * self.MAX_BUFFER_SIZE,
        )
        self.max_concurrent_auth = self.hash_permits.permits
        self.block_private_ranges = block_private_ranges
        self.allow_localhost = allow_localhost
        self.blocked_hosts = blocked_hosts or []
        # Matching the requested name stops a client that asks by name. A client that
        # looks the name up itself and asks for the literal is asking for the same
        # machine, so what the blocked names resolve to is refused as well. Kept per name
        # so a name that will not resolve this round keeps its last good answer instead of
        # falling open, and flattened into one set because the check runs on every
        # request.
        self._blocked_addresses_by_host: dict[str, frozenset[str]] = {}
        self._blocked_addresses: frozenset[str] = frozenset()
        self._blocked_host_watch: Optional[asyncio.Task[None]] = None
        self.max_failed_attempts = max_failed_attempts
        self.rate_limit_per_minute = rate_limit_per_minute
        self._lockout_seconds = lockout_duration_minutes * 60

        self._server: Optional[asyncio.Server] = None
        self._handler_tasks: dict[asyncio.Future[None], asyncio.StreamWriter] = {}
        self._connections: dict[str, ConnectionInfo] = {}
        self._running = False
        self._started_at: Optional[datetime] = None

        # Each handler holds a slot for its whole lifetime, including the argon2 hash,
        # which reserves 64 MB per verification. Without the cap N simultaneous clients
        # reserve N times that and the kernel kills the process.
        # Bounded rather than plain: a plain Semaphore accepts a release it never issued
        # and silently grows its value, so one double-release would raise this cap for
        # the rest of the run with nothing to show for it. This one raises instead.
        self._connection_slots = asyncio.BoundedSemaphore(max_connections)

        # Deliberately a second cap rather than a larger first one, because the two
        # answer different questions: how many clients may be connected at once, versus
        # how much memory password hashing may hold at once. Collapsing them hides the
        # fact that the connection cap does not bound hashing at all — the hash runs on
        # asyncio's default executor, sized min(32, cpu_count + 4), so peak argon2
        # memory used to follow the host's core count rather than any setting here.
        # Peak is permits x ARGON2_MEMORY_COST, which is why the count comes from the
        # memory budget rather than a fixed number that is the same on a 1 GB VPS and a
        # 64 GB host.
        # A blocking permit rather than an asyncio one because it is taken inside the
        # worker thread: an asyncio permit has to be taken on the loop before the thread
        # is handed the job, and a handshake that times out while its job is still queued
        # cancels that job before it ever runs, so nothing releases the permit. Enough of
        # those and the cap sits at zero with every later login blocked for good.
        self._auth_slots = threading.BoundedSemaphore(self.max_concurrent_auth)

        # The pool can be brought down while the server runs and put back up to the size
        # it started at, never past it: permits are removed by taking them and holding
        # them, and a BoundedSemaphore refuses a release it never issued. That ceiling
        # is worth keeping rather than working around, because it means the worst a bug
        # in the re-sizing can do is make logins slower, never let more argon2 run at
        # once than this process was built for.
        self._auth_slots_initial = self.max_concurrent_auth
        self._parked_auth_slots = 0
        self._budget_watch_stop = threading.Event()
        self._budget_watch: Optional[threading.Thread] = None
        # One resize at a time. Two of them interleaved would both move
        # _parked_auth_slots and both release the same BoundedSemaphore, and the second
        # release past the initial value raises ValueError inside a daemon thread nobody
        # is watching. start() already refuses to run two watches at once; this covers the
        # API and the tests, which can call resize_auth_slots directly.
        self._auth_resize_lock = threading.Lock()

        # Said out loud once, at startup. An operator seeing slow logins otherwise has no
        # way to tell that the process read a 256 MiB ceiling and allowed itself one hash.
        # A plan that does not fit under the ceiling is a warning rather than a note: the
        # count is still used, because refusing to serve is a certain outage in place of
        # a possible one, but it must not go past unremarked.
        say = logger.warning if self.hash_permits.exceeds_budget else logger.info
        say(
            "Password hashing limit",
            permits=self.max_concurrent_auth,
            set_by_operator=self.hash_permits.set_by_operator,
            exceeds_budget=self.hash_permits.exceeds_budget,
            budget_mib=self.hash_permits.budget.usable_bytes // MIB,
            budget_source=self.hash_permits.budget.source,
            budget_detail=self.hash_permits.budget.detail,
            budget_measured=self.hash_permits.budget.measured,
            cores=os.cpu_count(),
            reason=self.hash_permits.reason,
        )

        # Connection callback for monitoring
        self._on_connection: Optional[Callable[[ConnectionInfo], Awaitable[None]]] = None

        # User-specific listeners: port -> (server, username)
        self._user_listeners: dict[int, tuple[asyncio.Server, str]] = {}

        # Dynamic bridge creation support
        self._bridge_lock = asyncio.Lock()
        self._dynamic_connectors: dict[str, TorBridgeConnector] = {}
        self._next_bridge_port = bridge_base_port
        # bridge_type -> monotonic timestamp of the last failed start
        self._bridge_failures: dict[str, float] = {}

        # Both of these are keyed by values a client chooses, so both are swept on insert
        # and capped at MAX_TRACKED_ENTRIES rather than allowed to grow with the traffic.
        # (source address, username) -> failed logins
        self._auth_failures: dict[tuple[str, str], LockoutState] = {}
        # username -> requests in the open window, shared by every connection that user holds
        self._user_requests: dict[str, RateLimitState] = {}

        # username -> failed logins from anywhere. Only usernames the credential store
        # actually holds get an entry, so this one is the size of the user list rather than
        # something a client can grow, and it needs no cap and no eviction. That is the
        # point: the capped map above can be flushed by a client that invents enough
        # usernames, and it gives each new source address its own budget.
        self._account_failures: dict[str, LockoutState] = {}

        # (source address, username) -> when that source last authenticated as that user.
        # Keyed by a client-chosen value like the maps above, but an entry costs a correct
        # password, so it is capped on insert only to bound a caller cycling addresses.
        self._last_success: dict[tuple[str, str], float] = {}

        # User-aware logger for respecting per-user logging preferences
        self._user_logger = UserAwareLogger(auth_manager) if auth_manager else None

    def _should_log_user(self, username: Optional[str]) -> bool:
        """Check if logging is enabled for a user."""
        if username is None or self.auth_manager is None:
            return True
        logging_enabled = self.auth_manager.get_user_logging_enabled(username)
        return logging_enabled if logging_enabled is not None else True

    def _log_if_allowed(
        self, level: str, event: str, username: Optional[str] = None, **kwargs
    ) -> None:
        """Log a message only if the user allows logging."""
        if not self._should_log_user(username):
            return
        log_method = getattr(logger, level)
        if username:
            log_method(event, username=username, **kwargs)
        else:
            log_method(event, **kwargs)

    def _start_handler(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        allowed_user: str | None = None,
    ) -> None:
        """Start and retain a client handler until all of its cleanup has finished."""
        task = asyncio.create_task(self._handle_client(reader, writer, allowed_user=allowed_user))
        self._handler_tasks[task] = writer
        task.add_done_callback(self._finish_handler)

    def _finish_handler(self, task: asyncio.Future[None]) -> None:
        """Forget a completed handler and close its admitted client transport."""
        writer = self._handler_tasks.pop(task, None)
        if writer is not None:
            writer.close()

    def _make_user_handler(
        self, allowed_user: str
    ) -> Callable[[asyncio.StreamReader, asyncio.StreamWriter], None]:
        """Create a client handler that only allows a specific user."""

        def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            self._start_handler(reader, writer, allowed_user=allowed_user)

        return handler

    async def start_user_listener(self, username: str, port: int) -> bool:
        """
        Start a dedicated listener for a specific user.

        Args:
            username: The username that is allowed to connect on this port
            port: The port to listen on

        Returns:
            True if listener started successfully, False otherwise
        """
        if port in self._user_listeners:
            logger.warning("Port already has a listener", port=port)
            return False

        try:
            server = await asyncio.start_server(
                self._make_user_handler(username),
                self.host,
                port,
                reuse_address=True,
            )

            self._user_listeners[port] = (server, username)
            addr = server.sockets[0].getsockname()
            logger.info("User listener started", username=username, host=addr[0], port=addr[1])
            return True
        except OSError as e:
            logger.error(
                "Failed to start user listener", username=username, port=port, error=str(e)
            )
            return False

    async def stop_user_listener(self, port: int) -> bool:
        """
        Stop a user-specific listener.

        Args:
            port: The port of the listener to stop

        Returns:
            True if stopped successfully, False if not found
        """
        if port not in self._user_listeners:
            return False

        server, username = self._user_listeners.pop(port)
        server.close()
        await server.wait_closed()
        logger.info("User listener stopped", username=username, port=port)
        return True

    def get_user_listeners(self) -> dict[int, str]:
        """Get all active user-specific listeners (port -> username)."""
        return {port: username for port, (_, username) in self._user_listeners.items()}

    def _park_one_auth_slot(self, deadline: float) -> bool:
        """Take one permit out of the pool and hold it, or give up.

        False means the permit is still in use and the caller should leave it for the
        next round. The wait is broken into slices so that a server shutting down is not
        held behind a hash that has just started.
        """
        while not self._budget_watch_stop.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            if self._auth_slots.acquire(
                timeout=min(remaining, self.AUTH_RESIZE_POLL_SECONDS)
            ):
                return True
        return False

    def resize_auth_slots(self) -> None:
        """Read the memory ceiling again and bring the permit pool to what it now allows.

        Shrinking is the direction that matters. A ceiling lowered under a running
        process leaves it planning for memory it no longer has, and nothing tells it so
        until the kernel kills it. Permits are removed by taking them and not giving them
        back, which waits for a hash already running instead of interrupting it, and a
        permit that cannot be taken this time is simply left for the next round.

        The whole resize shares one deadline rather than giving each permit its own.
        Fifteen permits each allowed a full interval is several minutes inside a method
        the shutdown path waits on, and every one of those intervals is spent holding a
        picture of the budget that is already a round out of date.

        An operator who set the count by hand is left alone. They can see the machine
        and this code cannot, and a number quietly overridden is worse than one that is
        wrong on purpose.
        """
        if self.hash_permits.set_by_operator:
            return

        with self._auth_resize_lock:
            relay_reserve_bytes = self.max_connections * 2 * self.MAX_BUFFER_SIZE
            budget = read_memory_budget()
            try:
                chosen = choose_hash_permits(
                    None, relay_reserve_bytes=relay_reserve_bytes, budget=budget
                )
            except MemoryCeilingTooLow as e:
                # The ceiling has been lowered under a process that is already serving.
                # Refusing to start is not on offer here, and holding the count it had is
                # the one answer that is certainly wrong, so the pool goes to its floor
                # and the log carries the arithmetic that sent it there.
                chosen = HashPermits(
                    permits=MIN_PERMITS,
                    budget=budget,
                    set_by_operator=False,
                    exceeds_budget=True,
                    reason=f"{MIN_PERMITS} permit, the floor. {e}",
                )
            wanted = min(chosen.permits, self._auth_slots_initial)
            live = self._auth_slots_initial - self._parked_auth_slots
            if wanted == live:
                return

            deadline = time.monotonic() + self.BUDGET_RECHECK_SECONDS
            for _ in range(live - wanted):
                if not self._park_one_auth_slot(deadline):
                    break
                self._parked_auth_slots += 1
            for _ in range(wanted - live):
                self._auth_slots.release()
                self._parked_auth_slots -= 1

            now_live = self._auth_slots_initial - self._parked_auth_slots
            if now_live == live:
                return
            self.max_concurrent_auth = now_live
            self.hash_permits = chosen

        logger.warning(
            "Password hashing limit changed",
            permits=now_live,
            was=live,
            started_at=self._auth_slots_initial,
            budget_mib=chosen.budget.usable_bytes // MIB,
            budget_source=chosen.budget.source,
            budget_detail=chosen.budget.detail,
            reason=chosen.reason,
        )

    def _watch_memory_budget(self) -> None:
        """Re-read the ceiling on a timer until the server stops."""
        while not self._budget_watch_stop.wait(self.BUDGET_RECHECK_SECONDS):
            try:
                self.resize_auth_slots()
            except Exception as e:
                # A reading that fails must not take the watch down with it. The pool
                # keeps the count it has, which was safe a moment ago, and the next
                # round tries again.
                logger.warning("Could not re-read the memory budget", error=str(e))

    async def start(self) -> None:
        """Start the SOCKS5 server."""
        self._server = await asyncio.start_server(
            self._start_handler,
            self.host,
            self.port,
            reuse_address=True,
            backlog=self.LISTEN_BACKLOG,
        )

        self._running = True
        self._started_at = datetime.now()
        # Started here rather than in the constructor so that building a server without
        # running one, which the tests and the CLI both do, leaves no thread behind.
        #
        # Never two of them. A server stopped and started again can still have the
        # previous watch inside a permit acquisition, and clearing the stop event under it
        # would leave a pair that both move _parked_auth_slots and both release the same
        # BoundedSemaphore, the second release raising ValueError in a daemon thread
        # nobody reads. The stop event is still set from stop(), so the old one is on its
        # way out: waited for here rather than abandoned, because running with no watch at
        # all means a ceiling lowered under this process is never noticed.
        if self._budget_watch is not None and self._budget_watch.is_alive():
            self._budget_watch.join(timeout=self.BUDGET_RECHECK_SECONDS)
        if self._budget_watch is not None and self._budget_watch.is_alive():
            logger.warning(
                "Memory budget watch from the previous run has not stopped, "
                "the permit pool will not be re-sized",
                permits=self.max_concurrent_auth,
            )
        else:
            self._budget_watch_stop.clear()
            self._budget_watch = threading.Thread(
                target=self._watch_memory_budget, name="shadow9-memory-budget", daemon=True
            )
            self._budget_watch.start()
        # Resolved before the listener is announced, so the first client cannot arrive
        # while the address half of the block list is still empty. Bounded, because a
        # resolver that never answers would otherwise hold the proxy closed for as long
        # as it stayed silent; the watch fills the addresses in on its next round.
        if self.blocked_hosts:
            try:
                await asyncio.wait_for(
                    self.refresh_blocked_addresses(), timeout=self.CONNECTION_TIMEOUT
                )
            except (TimeoutError, OSError) as e:
                logger.warning(
                    "Blocked hosts were not resolved before the server opened",
                    error=str(e),
                )
            self._blocked_host_watch = asyncio.create_task(self._watch_blocked_addresses())
            # Said here rather than left in a docstring, because it is a limit of a
            # control the operator deliberately turned on and it cannot be seen from the
            # outside. A domain on the Tor route is handed upstream unresolved on
            # purpose, so the only check that can run on it is the name: a second name
            # for a blocked machine goes through. Closing that by resolving here would
            # send every Tor user's destination to this host's resolver, which is the
            # exposure Tor is there to avoid, and asking Tor to resolve it instead would
            # still not settle it, because the exit looks the name up again for the
            # connection that follows.
            logger.warning(
                "Blocked hosts are matched by name alone on the Tor route",
                blocked_hosts=len(self.blocked_hosts),
                checked="the name asked for on both routes, and what it resolves to on "
                "the direct route",
                not_checked="another name for a blocked machine, on the Tor route",
            )
        addr = self._server.sockets[0].getsockname()
        logger.info("SOCKS5 server started", host=addr[0], port=addr[1])

    async def stop(self) -> None:
        """Stop the SOCKS5 server and all user-specific listeners."""
        self._running = False

        self._budget_watch_stop.set()
        if self._budget_watch is not None:
            # It waits on the stop event rather than sleeping, and a resize checks that
            # same event between permits, so it comes back within one poll interval.
            self._budget_watch.join(timeout=self.BUDGET_RECHECK_SECONDS)
            if self._budget_watch.is_alive():
                # Kept rather than dropped. A forgotten thread is one that start() cannot
                # see, and a second watch beside it would corrupt the permit pool between
                # the two of them.
                logger.warning("Memory budget watch has not stopped yet")
            else:
                self._budget_watch = None

        if self._blocked_host_watch is not None:
            self._blocked_host_watch.cancel()
            # Awaited rather than left cancelled, so a lookup part-way through is finished
            # with before the loop this task belongs to is torn down.
            with suppress(asyncio.CancelledError):
                await self._blocked_host_watch
            self._blocked_host_watch = None

        # Stop accepting before taking the handler snapshot. The callbacks above create
        # and retain each task synchronously, so every admitted client is now represented.
        if self._server:
            self._server.close()

        user_listeners = list(self._user_listeners.items())
        for _, (server, _) in user_listeners:
            server.close()

        current_task = asyncio.current_task()
        handlers = [
            (task, writer)
            for task, writer in self._handler_tasks.items()
            if task is not current_task and not task.done()
        ]
        for task, writer in handlers:
            writer.close()
            task.cancel()
        if handlers:
            await asyncio.gather(*(task for task, _ in handlers), return_exceptions=True)
            await asyncio.gather(
                *(writer.wait_closed() for _, writer in handlers), return_exceptions=True
            )

        if self._server:
            await self._server.wait_closed()

        for port, (server, username) in user_listeners:
            await server.wait_closed()
            logger.info("User listener stopped", username=username, port=port)
        self._user_listeners.clear()

        # Stop all dynamically created Tor bridge connectors
        for bridge_type, connector in list(self._dynamic_connectors.items()):
            try:
                await connector.stop()
                logger.info("Dynamic Tor connector stopped", bridge_type=bridge_type)
            except Exception as e:
                logger.warning(
                    "Error stopping dynamic connector", bridge_type=bridge_type, error=str(e)
                )
        self._dynamic_connectors.clear()
        self._bridge_failures.clear()
        self._auth_failures.clear()
        self._account_failures.clear()
        self._user_requests.clear()
        self._last_success.clear()
        self._started_at = None

        # Flush any pending credential saves
        if self.auth_manager:
            self.auth_manager.flush_credentials()

        logger.info("SOCKS5 server stopped")

    async def serve_forever(self) -> None:
        """Run the server until stopped."""
        if not self._server:
            await self.start()

        async with self._server:
            await self._server.serve_forever()

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        allowed_user: Optional[str] = None,
    ) -> None:
        """
        Handle a new client connection.

        Args:
            reader: Stream reader for client connection
            writer: Stream writer for client connection
            allowed_user: If set, only this username is allowed to authenticate
        """
        client_addr = writer.get_extra_info("peername")
        conn_id = f"{client_addr[0]}:{client_addr[1]}"
        username: Optional[str] = None
        target_writer: Optional[asyncio.StreamWriter] = None

        # Only log new connection if no user restriction (can't filter yet)
        # For user-specific listeners, we defer logging until we know the user
        if allowed_user is None:
            logger.debug("New connection", client=conn_id)

        # Refused rather than queued. A waiting handler still holds its accepted socket,
        # so queueing a flood trades bounded memory for unbounded descriptors, which is
        # the other way this process dies. There is no await between the check and the
        # acquire, and acquire() returns without suspending while a slot is free, so no
        # other handler can take the last slot in between.
        if self._connection_slots.locked():
            logger.warning(
                "Connection limit reached, refusing client",
                client=conn_id,
                max_connections=self.max_connections,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return

        # Acquired outside the try so a cancelled wait never reaches the release below
        await self._connection_slots.acquire()

        try:
            # StreamWriter.transport is the supported handle for this; the reader's
            # transport attribute is private and can disappear between asyncio releases
            transport = writer.transport
            if hasattr(transport, "set_write_buffer_limits"):
                transport.set_write_buffer_limits(high=self.MAX_BUFFER_SIZE)

            # Perform SOCKS5 handshake with authentication
            username = await asyncio.wait_for(
                self._socks5_handshake(reader, writer), timeout=self.CONNECTION_TIMEOUT
            )

            if username is None:
                return

            # Check if this listener is restricted to a specific user
            if allowed_user is not None and username != allowed_user:
                self._log_if_allowed(
                    "warning",
                    "User not allowed on this port",
                    username=username,
                    allowed_user=allowed_user,
                )
                return

            # Get user settings from auth manager
            user_settings = {}
            if self.auth_manager and username:
                user_settings = self.auth_manager.get_user_info(username) or {}

            # Get connection request
            target = await asyncio.wait_for(
                self._socks5_request(reader, writer), timeout=self.CONNECTION_TIMEOUT
            )

            if target is None:
                return

            target_host, target_port = target

            # Check port restrictions for this user
            allowed_ports = user_settings.get("allowed_ports")
            if allowed_ports and target_port not in allowed_ports:
                self._log_if_allowed(
                    "warning",
                    "Port not allowed for user",
                    username=username,
                    port=target_port,
                    allowed=allowed_ports,
                )
                await self._send_reply(writer, Socks5Reply.NOT_ALLOWED)
                return

            if self._is_blocked_host(target_host):
                self._log_if_allowed(
                    "warning", "Destination host is blocked", username=username, host=target_host
                )
                await self._send_reply(writer, Socks5Reply.NOT_ALLOWED)
                return

            # A literal address is settled here because it cannot turn into something
            # else. A domain is checked against its resolution further down instead: the
            # name on its own says nothing about where it points.
            if self._is_ip(target_host):
                # Asking for the address a blocked name resolves to is asking for the
                # blocked machine, whoever did the lookup.
                if self._is_blocked_address(target_host):
                    self._log_if_allowed(
                        "warning",
                        "Destination address belongs to a blocked host",
                        username=username,
                        address=target_host,
                    )
                    await self._send_reply(writer, Socks5Reply.NOT_ALLOWED)
                    return
                if not self._is_allowed_address(ip_address(target_host)):
                    self._log_if_allowed(
                        "warning",
                        "Destination address refused by policy",
                        username=username,
                        host=target_host,
                    )
                    await self._send_reply(writer, Socks5Reply.NOT_ALLOWED)
                    return

            # One count per user, held on the server, so opening more connections buys no
            # extra requests. A per-connection counter would limit nothing.
            user_rate_limit = user_settings.get("rate_limit")
            request_limit = (
                user_rate_limit if user_rate_limit is not None else self.rate_limit_per_minute
            )
            if self._rate_limit_exceeded(username, request_limit):
                self._log_if_allowed(
                    "warning", "Rate limit exceeded", username=username, limit=request_limit
                )
                await self._send_reply(writer, Socks5Reply.NOT_ALLOWED)
                return

            # Get user's bridge type
            bridge_type = user_settings.get("bridge_type", "none")

            # Create connection info with user settings
            conn_info = ConnectionInfo(
                client_addr=client_addr,
                target_addr=target_host,
                target_port=target_port,
                username=username,
                use_tor=user_settings.get("use_tor", True),
                bridge_type=bridge_type,
                security_level=user_settings.get("security_level", "basic"),
            )
            self._connections[conn_id] = conn_info

            # Check if user wants Tor routing
            use_tor = conn_info.use_tor

            # A domain on the Tor route is handed to the upstream unresolved on purpose.
            # Resolving it here to run the address policy over it would send every Tor
            # user's destination name to this machine's resolver, which is the exposure
            # Tor is being used to avoid. The operator's name list is already applied to
            # both routes above, and a literal address is settled above as well.
            # Select the appropriate upstream proxy based on bridge type
            upstream_proxy = None
            if use_tor:
                upstream_proxy = await self._get_or_create_bridge_proxy(bridge_type)
                if upstream_proxy is None and self.upstream_proxy:
                    upstream_proxy = self.upstream_proxy

            # Connect to target
            if upstream_proxy and use_tor:
                is_onion = target_host.endswith(".onion")
                if is_onion:
                    connect_timeout = self.ONION_CONNECTION_TIMEOUT
                elif bridge_type in ("snowflake", "obfs4"):
                    connect_timeout = self.BRIDGE_CONNECTION_TIMEOUT
                else:
                    connect_timeout = self.CONNECTION_TIMEOUT

                try:
                    target_reader, target_writer = await asyncio.wait_for(
                        self._connect_via_proxy(
                            target_host,
                            target_port,
                            proxy=upstream_proxy,
                            socks_username=username,
                            socks_password=username,
                        ),
                        timeout=connect_timeout,
                    )
                except UpstreamProxyUnreachable:
                    # The SOCKS port stopped accepting, so the Tor process behind it is
                    # gone. Drop it here or every later connection routes into a corpse.
                    await self._drop_bridge_proxy(bridge_type)
                    raise
                self._log_if_allowed(
                    "debug",
                    "Routing through Tor (isolated circuit)",
                    username=username,
                    bridge=conn_info.bridge_type,
                    security=conn_info.security_level,
                )
            else:
                if use_tor:
                    # Falling through to a direct connection here would hand the target
                    # the address the user is running Tor to keep it from seeing, and the
                    # old code still answered SUCCEEDED, so nothing told them. Failing is
                    # the only answer that keeps the promise.
                    self._log_if_allowed(
                        "error",
                        "Refusing connection, Tor routing has no upstream proxy",
                        username=username,
                        bridge=bridge_type,
                    )
                    await self._send_reply(writer, Socks5Reply.GENERAL_FAILURE)
                    return

                connect_hosts = await asyncio.wait_for(
                    self._resolve_allowed_address(target_host, target_port, username),
                    timeout=self.CONNECTION_TIMEOUT,
                )
                if not connect_hosts:
                    await self._send_reply(writer, Socks5Reply.NOT_ALLOWED)
                    return

                target_reader, target_writer = await asyncio.wait_for(
                    self._open_first_reachable(connect_hosts, target_port),
                    timeout=self.CONNECTION_TIMEOUT,
                )
                self._log_if_allowed(
                    "debug",
                    "Direct connection",
                    username=username,
                    security=conn_info.security_level,
                )

            # Send success reply
            await self._send_reply(writer, Socks5Reply.SUCCEEDED)

            # Notify connection callback
            if self._on_connection:
                try:
                    await self._on_connection(conn_info)
                except Exception as e:
                    self._log_if_allowed(
                        "error",
                        "Connection monitoring callback failed",
                        username=username,
                        client=conn_id,
                        error=str(e),
                    )

            # Setup DPI bypass if security level requires it
            dpi_bypass = None
            if conn_info.security_level in ("moderate", "paranoid"):
                security_config = get_security_preset(SecurityLevel(conn_info.security_level))
                if security_config.dpi_bypass.enabled:
                    dpi_bypass = DPIBypass(security_config.dpi_bypass)
                    self._log_if_allowed(
                        "debug",
                        "DPI bypass enabled",
                        username=username,
                        security=conn_info.security_level,
                    )

            # Relay data between client and target
            await self._relay(reader, writer, target_reader, target_writer, conn_info, dpi_bypass)

        except TimeoutError:
            self._log_if_allowed("warning", "Connection timeout", username=username, client=conn_id)
            await self._send_reply(writer, Socks5Reply.TTL_EXPIRED)
        except asyncio.IncompleteReadError:
            # readexactly only runs against the client, and it ends this way when the
            # client hangs up part-way through its greeting or request. That is ordinary,
            # not an error to investigate: the API's status check connects and closes
            # without a greeting on every poll, so a dashboard on a five-second timer
            # wrote seventeen thousand error lines a day into the log an operator greps
            # after a crash. No reply either, since there is nobody left to read it.
            self._log_if_allowed(
                "debug",
                "Client disconnected before finishing its request",
                username=username,
                client=conn_id,
            )
        except ConnectionRefusedError:
            self._log_if_allowed(
                "warning", "Connection refused by target", username=username, client=conn_id
            )
            await self._send_reply(writer, Socks5Reply.CONNECTION_REFUSED)
        except OSError as e:
            if "Network is unreachable" in str(e):
                await self._send_reply(writer, Socks5Reply.NETWORK_UNREACHABLE)
            elif "No route to host" in str(e):
                await self._send_reply(writer, Socks5Reply.HOST_UNREACHABLE)
            else:
                await self._send_reply(writer, Socks5Reply.GENERAL_FAILURE)
            self._log_if_allowed(
                "error", "Connection error", username=username, client=conn_id, error=str(e)
            )
        except Exception as e:
            self._log_if_allowed(
                "error", "Unexpected error", username=username, client=conn_id, error=str(e)
            )
            await self._send_reply(writer, Socks5Reply.GENERAL_FAILURE)
        finally:
            self._connection_slots.release()
            if conn_id in self._connections:
                del self._connections[conn_id]
            # _relay closes this too, but the handler can raise before ever reaching it
            if target_writer is not None:
                target_writer.close()
                with suppress(Exception):
                    await target_writer.wait_closed()
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _socks5_handshake(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> Optional[str]:
        """
        Perform SOCKS5 handshake with authentication.

        Returns the authenticated username, or None on failure.
        """
        # Read greeting: VER, NMETHODS, METHODS
        header = await reader.readexactly(2)
        version, nmethods = struct.unpack("!BB", header)

        if version != self.SOCKS_VERSION:
            logger.warning("Invalid SOCKS version", version=version)
            writer.close()
            return None

        # Read authentication methods
        methods = await reader.readexactly(nmethods)
        methods_set = set(methods)

        # We require username/password authentication
        if Socks5AuthMethod.USERNAME_PASSWORD not in methods_set:
            # No acceptable authentication method
            writer.write(struct.pack("!BB", self.SOCKS_VERSION, Socks5AuthMethod.NO_ACCEPTABLE))
            await writer.drain()
            logger.warning("No acceptable auth method")
            return None

        # Request username/password authentication
        writer.write(struct.pack("!BB", self.SOCKS_VERSION, Socks5AuthMethod.USERNAME_PASSWORD))
        await writer.drain()

        # Authenticate
        return await self._authenticate(reader, writer)

    async def _authenticate(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> Optional[str]:
        """
        Perform username/password authentication (RFC 1929).

        Returns the username on success, None on failure.
        """
        # Read auth version and username length
        auth_header = await reader.readexactly(2)
        auth_version, ulen = struct.unpack("!BB", auth_header)

        if auth_version != self.AUTH_VERSION:
            logger.warning("Invalid auth version", version=auth_version)
            return None

        # Validate username length
        if ulen == 0 or ulen > 255:
            logger.warning("Invalid username length", length=ulen)
            await self._send_auth_response(writer, False)
            return None

        # Read username
        username = (await reader.readexactly(ulen)).decode("utf-8", errors="replace")

        # Read password length and password
        plen = struct.unpack("!B", await reader.readexactly(1))[0]

        if plen == 0 or plen > 255:
            logger.warning("Invalid password length", length=plen)
            await self._send_auth_response(writer, False)
            return None

        password = (await reader.readexactly(plen)).decode("utf-8", errors="replace")

        source = self._peer_address(writer)

        # A source that spent its own budget is refused before the hash. The account-wide
        # count is still kept, but it cannot refuse a new source before the password is
        # checked because that would let a crowd of addresses lock out the account owner.
        if self.max_failed_attempts > 0 and self._spent_attempts(
            self._auth_failures, (source, username), self.max_failed_attempts
        ):
            self._log_if_allowed(
                "warning",
                "Authentication refused, too many failed attempts",
                username=username,
                client=source,
            )
            await self._send_auth_response(writer, False)
            return None

        # Verify credentials. Argon2 is deliberately expensive, so running it inline
        # would stall every other connection on this loop for the duration of the hash.
        # Waiting here is safe where refusing was necessary for connections: every caller
        # already holds a connection slot, so the queue cannot be longer than
        # max_connections, and a waiter holds only its socket rather than 64 MiB.
        verified = False
        if self.auth_manager:
            verified = await self._verify_credentials(username, password)

        if verified:
            self._record_auth_success(source, username)
            await self._send_auth_response(writer, True)
            return username
        else:
            self._record_auth_failure(source, username)
            # Only log failed auth if user doesn't exist or allows logging
            # (security: always log attempts for unknown users)
            self._log_if_allowed("warning", "Authentication failed", username=username)
            await self._send_auth_response(writer, False)
            return None

    async def _verify_credentials(self, username: str, password: str) -> bool:
        """Run one argon2 verification on a worker thread, holding a hashing permit for
        as long as the thread actually runs.

        The handshake is wrapped in a timeout, so this await can be cancelled. Cancelling
        an await does not stop a thread that has already started hashing, so a permit tied
        to the await would be handed back while 64 MiB is still held, and the next
        connection would start another hash on top of it. Taking the permit inside the
        worker ties it to the thread instead: the permit exists only while the thread that
        holds it is running, a thread waiting for one holds no argon2 memory, and a
        cancelled caller can neither release it early nor strand it.
        """

        def verify_under_permit() -> bool:
            with self._auth_slots:
                return self.auth_manager.verify(username, password)

        return await asyncio.to_thread(verify_under_permit)

    async def _send_auth_response(self, writer: asyncio.StreamWriter, success: bool) -> None:
        """Send authentication response."""
        status = 0x00 if success else 0x01
        writer.write(struct.pack("!BB", self.AUTH_VERSION, status))
        await writer.drain()

    async def _socks5_request(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> Optional[tuple[str, int]]:
        """
        Parse SOCKS5 connection request.

        Returns (target_host, target_port) or None on failure.
        """
        # Read request header: VER, CMD, RSV, ATYP
        header = await reader.readexactly(4)
        version, cmd, _, atyp = struct.unpack("!BBBB", header)

        if version != self.SOCKS_VERSION:
            logger.warning("Invalid SOCKS version in request", version=version)
            return None

        # Validate command
        try:
            command = Socks5Command(cmd)
        except ValueError:
            logger.warning("Invalid command", cmd=cmd)
            await self._send_reply(writer, Socks5Reply.COMMAND_NOT_SUPPORTED)
            return None

        if command not in self.allowed_commands:
            logger.warning("Command not allowed", command=command.name)
            await self._send_reply(writer, Socks5Reply.COMMAND_NOT_SUPPORTED)
            return None

        # Parse destination address
        try:
            addr_type = Socks5AddressType(atyp)
        except ValueError:
            logger.warning("Invalid address type", atyp=atyp)
            await self._send_reply(writer, Socks5Reply.ADDRESS_TYPE_NOT_SUPPORTED)
            return None

        # Read address based on type
        if addr_type == Socks5AddressType.IPV4:
            raw_addr = await reader.readexactly(4)
            target_host = socket.inet_ntoa(raw_addr)

        elif addr_type == Socks5AddressType.DOMAIN:
            domain_len = struct.unpack("!B", await reader.readexactly(1))[0]
            if domain_len == 0 or domain_len > 255:
                await self._send_reply(writer, Socks5Reply.GENERAL_FAILURE)
                return None
            target_host = (await reader.readexactly(domain_len)).decode("utf-8", errors="replace")

            # Basic domain validation
            if not self._validate_domain(target_host):
                logger.warning("Invalid domain", domain=target_host)
                await self._send_reply(writer, Socks5Reply.GENERAL_FAILURE)
                return None

        elif addr_type == Socks5AddressType.IPV6:
            raw_addr = await reader.readexactly(16)
            target_host = socket.inet_ntop(socket.AF_INET6, raw_addr)

        else:
            await self._send_reply(writer, Socks5Reply.ADDRESS_TYPE_NOT_SUPPORTED)
            return None

        # Read port
        target_port = struct.unpack("!H", await reader.readexactly(2))[0]

        if target_port == 0:
            logger.warning("Invalid port", port=target_port)
            await self._send_reply(writer, Socks5Reply.GENERAL_FAILURE)
            return None

        # Target info logged in _handle_client after user filtering check
        return target_host, target_port

    async def _send_reply(
        self,
        writer: asyncio.StreamWriter,
        reply: Socks5Reply,
        bind_addr: str = "0.0.0.0",
        bind_port: int = 0,
    ) -> None:
        """Send SOCKS5 reply to client."""
        try:
            # Build reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
            addr_bytes = socket.inet_aton(bind_addr)
            reply_data = struct.pack(
                "!BBBB4sH",
                self.SOCKS_VERSION,
                reply,
                0x00,  # Reserved
                Socks5AddressType.IPV4,
                addr_bytes,
                bind_port,
            )
            writer.write(reply_data)
            await writer.drain()
        except Exception as e:
            logger.error("Failed to send reply", error=str(e))

    async def _connect_via_proxy(
        self,
        target_host: str,
        target_port: int,
        proxy: Optional[tuple[str, int]] = None,
        socks_username: Optional[str] = None,
        socks_password: Optional[str] = None,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Connect to target via upstream SOCKS5 proxy.

        Args:
            target_host: Target hostname to connect to
            target_port: Target port to connect to
            proxy: Upstream proxy (host, port) - uses self.upstream_proxy if not provided
            socks_username: Optional SOCKS auth username (for Tor circuit isolation)
            socks_password: Optional SOCKS auth password (for Tor circuit isolation)

        When socks_username/password are provided, Tor's IsolateSOCKSAuth feature
        will assign a separate circuit for each unique username, giving each user
        their own exit IP.
        """
        # Use provided proxy or fall back to default
        upstream = proxy or self.upstream_proxy
        if not upstream:
            raise ConnectionError("No upstream proxy configured")

        proxy_host, proxy_port = upstream

        # Connect to upstream proxy
        try:
            reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
        except OSError as e:
            raise UpstreamProxyUnreachable(
                f"Cannot reach upstream proxy {proxy_host}:{proxy_port}"
            ) from e

        # Everything past this point owns an open socket. The caller wraps this coroutine
        # in asyncio.wait_for, so a timeout cancels it mid-await, and CancelledError does
        # not derive from Exception. Catching BaseException covers the raise and the
        # cancel with one closer instead of leaking a descriptor on every Tor timeout.
        try:
            # Determine auth method
            if socks_username and socks_password:
                # Use username/password auth for Tor circuit isolation
                writer.write(
                    struct.pack("!BBB", self.SOCKS_VERSION, 1, Socks5AuthMethod.USERNAME_PASSWORD)
                )
                await writer.drain()

                response = await reader.readexactly(2)
                if response[1] != Socks5AuthMethod.USERNAME_PASSWORD:
                    raise ConnectionError("Upstream proxy doesn't support username/password auth")

                # Send auth credentials (RFC 1929)
                username_bytes = socks_username.encode("utf-8")[:255]
                password_bytes = socks_password.encode("utf-8")[:255]
                auth_request = struct.pack("!BB", 0x01, len(username_bytes)) + username_bytes
                auth_request += struct.pack("!B", len(password_bytes)) + password_bytes
                writer.write(auth_request)
                await writer.drain()

                auth_response = await reader.readexactly(2)
                if auth_response[1] != 0x00:
                    raise ConnectionError("Upstream proxy authentication failed")
            else:
                # SOCKS5 handshake with no auth (legacy behavior)
                writer.write(struct.pack("!BBB", self.SOCKS_VERSION, 1, Socks5AuthMethod.NO_AUTH))
                await writer.drain()

                response = await reader.readexactly(2)
                if response[1] != Socks5AuthMethod.NO_AUTH:
                    raise ConnectionError("Upstream proxy requires authentication")

            # Send CONNECT request
            if target_host.endswith(".onion") or not self._is_ip(target_host):
                # Domain name
                domain_bytes = target_host.encode("utf-8")
                request = (
                    struct.pack(
                        "!BBBBB",
                        self.SOCKS_VERSION,
                        Socks5Command.CONNECT,
                        0x00,
                        Socks5AddressType.DOMAIN,
                        len(domain_bytes),
                    )
                    + domain_bytes
                    + struct.pack("!H", target_port)
                )
            else:
                # IP address. _is_ip accepts both families, so the family has to be read
                # off the parsed address rather than assumed: inet_aton parses IPv4 only
                # and raises on every v6 literal, which turned a destination Tor reaches
                # perfectly well into an unexplained failure
                address = ip_address(target_host)
                if address.version == 6:
                    request = struct.pack(
                        "!BBBB16sH",
                        self.SOCKS_VERSION,
                        Socks5Command.CONNECT,
                        0x00,
                        Socks5AddressType.IPV6,
                        address.packed,
                        target_port,
                    )
                else:
                    request = struct.pack(
                        "!BBBB4sH",
                        self.SOCKS_VERSION,
                        Socks5Command.CONNECT,
                        0x00,
                        Socks5AddressType.IPV4,
                        address.packed,
                        target_port,
                    )

            writer.write(request)
            await writer.drain()

            # Read response
            response = await reader.readexactly(4)
            if response[1] != Socks5Reply.SUCCEEDED:
                raise ConnectionError(f"Upstream proxy connection failed: {response[1]}")

            # Skip bound address
            atyp = response[3]
            if atyp == Socks5AddressType.IPV4:
                await reader.readexactly(4 + 2)
            elif atyp == Socks5AddressType.DOMAIN:
                dlen = struct.unpack("!B", await reader.readexactly(1))[0]
                await reader.readexactly(dlen + 2)
            elif atyp == Socks5AddressType.IPV6:
                await reader.readexactly(16 + 2)
        except BaseException:
            # close() is synchronous; awaiting wait_closed() here would raise again
            # while the task is already being cancelled
            writer.close()
            raise

        return reader, writer

    async def _get_or_create_bridge_proxy(self, bridge_type: str) -> Optional[tuple[str, int]]:
        """
        Get existing proxy for bridge_type or create a new Tor instance on demand.

        This method enables dynamic Tor instance creation when a user connects with
        a bridge_type that wasn't configured at server startup.

        Args:
            bridge_type: The bridge type string (e.g., "snowflake", "obfs4", "none")

        Returns:
            Tuple of (socks_host, socks_port) for the upstream proxy, or None if creation failed
        """
        # Check if we already have a proxy for this bridge type
        if bridge_type in self.upstream_proxies:
            return self.upstream_proxies[bridge_type]

        # Acquire lock to prevent multiple concurrent creations of the same bridge type
        async with self._bridge_lock:
            # Double-check after acquiring lock (another task may have created it)
            if bridge_type in self.upstream_proxies:
                return self.upstream_proxies[bridge_type]

            # A bridge that just failed to start will fail again the same way. Without
            # this the next client spawns another Tor process, and so does the one after.
            failed_at = self._bridge_failures.get(bridge_type)
            if failed_at is not None:
                if time.monotonic() - failed_at < self.BRIDGE_FAILURE_TTL:
                    logger.debug(
                        "Skipping bridge start, a recent attempt failed", bridge_type=bridge_type
                    )
                    return None
                del self._bridge_failures[bridge_type]

            # Don't try to create "none" bridge type dynamically - requires system Tor
            if bridge_type == "none":
                logger.warning(
                    "Cannot create 'none' bridge type dynamically - requires system Tor",
                    bridge_type=bridge_type,
                )
                return self.upstream_proxy  # Fall back to default if available

            # Try to parse the bridge type
            try:
                bridge_enum = BridgeType(bridge_type)
            except ValueError:
                logger.error(
                    "Unknown bridge type, cannot create dynamically", bridge_type=bridge_type
                )
                return None

            # Allocate a new port for this bridge
            bridge_port = self._next_bridge_port
            self._next_bridge_port += 1

            logger.info(
                "Creating dynamic Tor instance for new bridge type",
                bridge_type=bridge_type,
                port=bridge_port,
            )

            # Create and start the bridge connector
            bridge_config = BridgeConfig(
                enabled=True,
                bridge_type=bridge_enum,
                use_builtin_bridges=True,
            )
            connector = TorBridgeConnector(bridge_config, socks_port=bridge_port)

            try:
                socks_host, socks_port = await connector.start_tor_with_bridges()

                # Store the connector for cleanup and cache the proxy
                self._dynamic_connectors[bridge_type] = connector
                self.upstream_proxies[bridge_type] = (socks_host, socks_port)

                logger.info(
                    "Dynamic Tor instance created successfully",
                    bridge_type=bridge_type,
                    proxy=f"{socks_host}:{socks_port}",
                )

                return (socks_host, socks_port)

            except Exception as e:
                logger.error(
                    "Failed to create dynamic Tor instance", bridge_type=bridge_type, error=str(e)
                )
                self._bridge_failures[bridge_type] = time.monotonic()
                # Nothing bound this port, so hand it back rather than burning one per
                # attempt. Safe under the lock, which is the only place it is assigned.
                if self._next_bridge_port == bridge_port + 1:
                    self._next_bridge_port = bridge_port
                # Cleanup on failure
                try:
                    await connector.stop()
                except Exception:
                    pass
                return None

    async def _drop_bridge_proxy(self, bridge_type: str) -> None:
        """Stop and forget the dynamic Tor instance backing a bridge type.

        Called when its SOCKS port stops accepting connections, which means the Tor
        process behind it is gone. Removing both entries lets the next client build a
        fresh instance instead of routing into a dead one for the rest of the run.
        """
        async with self._bridge_lock:
            connector = self._dynamic_connectors.pop(bridge_type, None)
            if connector is None:
                # A statically configured proxy is not ours to remove
                return

            self.upstream_proxies.pop(bridge_type, None)
            try:
                await connector.stop()
            except Exception as e:
                logger.warning(
                    "Error stopping dead bridge connector", bridge_type=bridge_type, error=str(e)
                )
            logger.info("Dropped unreachable bridge proxy", bridge_type=bridge_type)

    async def _relay(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        target_reader: asyncio.StreamReader,
        target_writer: asyncio.StreamWriter,
        conn_info: ConnectionInfo,
        dpi_bypass: Optional[DPIBypass] = None,
    ) -> None:
        """Relay data between client and target with optional DPI bypass."""

        async def send_eof(writer: asyncio.StreamWriter) -> None:
            """Finish one write direction without discarding the peer's remaining input."""
            if not writer.can_write_eof():
                writer.close()
                return
            try:
                writer.write_eof()
                await asyncio.wait_for(writer.drain(), timeout=self.CONNECTION_TIMEOUT)
            except (TimeoutError, ConnectionError, OSError, NotImplementedError):
                writer.close()

        async def relay_to_target() -> None:
            first_packet = True
            try:
                while True:
                    data = await asyncio.wait_for(
                        client_reader.read(self.MAX_BUFFER_SIZE), timeout=self.RELAY_TIMEOUT
                    )
                    if not data:
                        break

                    # Apply DPI bypass to first packet (TLS ClientHello)
                    if first_packet and dpi_bypass and dpi_bypass.config.enabled:
                        first_packet = False
                        is_tls = data[0] == 0x16
                        record_complete = not is_tls
                        if is_tls:
                            first_record = bytearray(data)
                            deadline = asyncio.get_running_loop().time() + self.TLS_RECORD_TIMEOUT

                            while (
                                len(first_record) < 5
                                and len(first_record) < self.MAX_BUFFER_SIZE
                            ):
                                if len(first_record) >= 2 and first_record[1] != 0x03:
                                    is_tls = False
                                    record_complete = True
                                    break
                                remaining_time = deadline - asyncio.get_running_loop().time()
                                if remaining_time <= 0:
                                    break
                                try:
                                    more = await asyncio.wait_for(
                                        client_reader.read(
                                            min(
                                                5 - len(first_record),
                                                self.MAX_BUFFER_SIZE - len(first_record),
                                            )
                                        ),
                                        timeout=remaining_time,
                                    )
                                except TimeoutError:
                                    break
                                if not more:
                                    break
                                first_record.extend(more)

                            if len(first_record) >= 2 and first_record[1] != 0x03:
                                is_tls = False
                                record_complete = True
                            elif len(first_record) >= 5:
                                record_size = 5 + int.from_bytes(first_record[3:5], "big")
                                if record_size <= self.MAX_BUFFER_SIZE:
                                    while len(first_record) < record_size:
                                        remaining_time = (
                                            deadline - asyncio.get_running_loop().time()
                                        )
                                        if remaining_time <= 0:
                                            break
                                        try:
                                            more = await asyncio.wait_for(
                                                client_reader.read(record_size - len(first_record)),
                                                timeout=remaining_time,
                                            )
                                        except TimeoutError:
                                            break
                                        if not more:
                                            break
                                        first_record.extend(more)
                                    record_complete = len(first_record) >= record_size

                            data = bytes(first_record)

                        if not is_tls or record_complete:
                            fragments = dpi_bypass.fragment_for_bypass(data)
                        else:
                            fragments = [data]
                        for i, fragment in enumerate(fragments):
                            target_writer.write(fragment)
                            # drain() waits on the peer reading; read() has RELAY_TIMEOUT
                            # but this side had none, so a stalled peer hung the task
                            await asyncio.wait_for(
                                target_writer.drain(), timeout=self.CONNECTION_TIMEOUT
                            )
                            # Small delay between fragments to ensure separate packets
                            if i < len(fragments) - 1:
                                await asyncio.sleep(0.001)
                        conn_info.bytes_sent += len(data)
                    else:
                        target_writer.write(data)
                        await asyncio.wait_for(
                            target_writer.drain(), timeout=self.CONNECTION_TIMEOUT
                        )
                        conn_info.bytes_sent += len(data)
                await send_eof(target_writer)
            except (TimeoutError, ConnectionError, OSError) as e:
                self._log_if_allowed(
                    "debug",
                    "Relay to target ended",
                    username=conn_info.username,
                    target=f"{conn_info.target_addr}:{conn_info.target_port}",
                    error=str(e) or type(e).__name__,
                )
                target_writer.close()
            except BaseException:
                target_writer.close()
                raise

        async def relay_to_client() -> None:
            try:
                while True:
                    data = await asyncio.wait_for(
                        target_reader.read(self.MAX_BUFFER_SIZE), timeout=self.RELAY_TIMEOUT
                    )
                    if not data:
                        break
                    client_writer.write(data)
                    await asyncio.wait_for(client_writer.drain(), timeout=self.CONNECTION_TIMEOUT)
                    conn_info.bytes_received += len(data)
                await send_eof(client_writer)
            except (TimeoutError, ConnectionError, OSError) as e:
                self._log_if_allowed(
                    "debug",
                    "Relay to client ended",
                    username=conn_info.username,
                    target=f"{conn_info.target_addr}:{conn_info.target_port}",
                    error=str(e) or type(e).__name__,
                )
                client_writer.close()
            except BaseException:
                client_writer.close()
                raise

        # Run both relay tasks concurrently
        results = await asyncio.gather(relay_to_target(), relay_to_client(), return_exceptions=True)

        # return_exceptions hides anything the two handlers above did not expect,
        # so an unexpected relay failure is silent unless it is read back out here
        for direction, result in zip(("to_target", "to_client"), results, strict=True):
            if isinstance(result, BaseException):
                self._log_if_allowed(
                    "error",
                    "Relay failed",
                    username=conn_info.username,
                    direction=direction,
                    target=f"{conn_info.target_addr}:{conn_info.target_port}",
                    error=str(result) or type(result).__name__,
                )

        target_writer.close()
        client_writer.close()

        # Only log connection details if user allows logging
        self._log_if_allowed(
            "info",
            "Connection closed",
            username=conn_info.username,
            target=f"{conn_info.target_addr}:{conn_info.target_port}",
            sent=conn_info.bytes_sent,
            received=conn_info.bytes_received,
        )

    @staticmethod
    def _validate_domain(domain: str) -> bool:
        """Validate domain name format."""
        if not domain or len(domain) > 253:
            return False

        # Allow .onion domains
        if domain.endswith(".onion"):
            return len(domain) > 7

        # Basic validation - allow alphanumeric, hyphen, dots
        allowed = set("abcdefghijklmnopqrstuvwxyz0123456789.-")
        return all(c in allowed for c in domain.lower())

    @staticmethod
    def _is_ip(addr: str) -> bool:
        """Check if address is an IP address."""
        try:
            ip_address(addr)
            return True
        except ValueError:
            return False

    @staticmethod
    def _peer_address(writer: asyncio.StreamWriter) -> str:
        """Source address of the client, or an empty string once the socket is gone."""
        peer = writer.get_extra_info("peername")
        return peer[0] if peer else ""

    @staticmethod
    def _is_blocked_destination(addr: IPv4Address | IPv6Address) -> bool:
        """Reject anything not reachable on the public internet, plus multicast and reserved space.

        This asks is_global rather than is_private because the carrier-grade NAT range
        100.64.0.0/10 answers False to both, and a proxy client has no business reaching
        the operator's carrier network through this server.
        """
        return not addr.is_global or addr.is_multicast or addr.is_reserved or addr.is_unspecified

    def _is_allowed_address(self, addr: IPv4Address | IPv6Address) -> bool:
        """Whether the configured policy permits connecting to this address."""
        if not self.block_private_ranges:
            return True
        if self.allow_localhost and addr.is_loopback:
            return True
        return not self._is_blocked_destination(addr)

    def _is_blocked_host(self, host: str) -> bool:
        """Whether the requested name matches the operator's block list.

        A parent entry covers everything under it, so blocking example.com also blocks
        www.example.com, which is what an operator writing one line expects.

        This is the name half of the block. _is_blocked_address is the other half, and
        covers the client that resolves the name itself and asks for the literal.
        """
        if not self.blocked_hosts:
            return False
        candidate = host.lower().rstrip(".")
        for blocked in self.blocked_hosts:
            entry = blocked.strip().lower().rstrip(".")
            if entry and (candidate == entry or candidate.endswith("." + entry)):
                return True
        return False

    def _is_blocked_address(self, literal: str) -> bool:
        """Whether this address is one the blocked names currently resolve to.

        Only what refresh_blocked_addresses last looked up. A name never resolved is not
        in here, which is why the name check runs as well rather than instead.
        """
        return literal in self._blocked_addresses

    async def _resolve_blocked_host(self, entry: str, limit: asyncio.Semaphore) -> None:
        """Look one blocked name up, or leave it with the addresses it gave last.

        A name that does not answer keeps its previous addresses rather than losing them:
        a resolver unreachable for a moment must not open a block the operator asked for.
        A name that has never answered has nothing to keep, which is why the name check
        runs as well rather than instead.

        Args:
            entry: The blocked name, already stripped, lowercased and without its
                trailing dot
            limit: How many of these may be in flight at once, shared across the round
        """
        loop = asyncio.get_running_loop()
        try:
            async with limit:
                resolved = await asyncio.wait_for(
                    loop.getaddrinfo(entry, None, type=socket.SOCK_STREAM),
                    timeout=self.BLOCKED_HOST_RESOLVE_TIMEOUT,
                )
        except (TimeoutError, OSError) as e:
            logger.warning(
                "Blocked host did not resolve, keeping its last known addresses",
                host=entry,
                error=str(e),
            )
            return
        # A scoped literal such as fe80::1%eth0 is not comparable to what a client sends,
        # and the scope is not part of the address either way.
        self._blocked_addresses_by_host[entry] = frozenset(
            str(sockaddr[0]).split("%")[0] for *_, sockaddr in resolved
        )

    async def refresh_blocked_addresses(self) -> None:
        """Look every blocked name up and hold the addresses it answers with now.

        Run at startup and again on a timer. A name that resolves has its previous answer
        replaced rather than added to, so addresses a name has moved off do not pile up
        and start refusing whoever holds them now. _resolve_blocked_host has what happens
        to a name that will not answer.

        The Tor route hands the name upstream without resolving it, so no address can be
        screened there and only the name check applies. That is the same limit the
        address policy already has on that route, and start() says so out loud.
        """
        if not self.blocked_hosts:
            self._blocked_addresses_by_host = {}
            self._blocked_addresses = frozenset()
            return

        entries = []
        for blocked in self.blocked_hosts:
            entry = blocked.strip().lower().rstrip(".")
            if entry:
                entries.append(entry)

        # Each name is bounded and answered for on its own, so one that never comes back
        # costs its own timeout and nothing else. Run one at a time and in order, the
        # first silent name in the list was the last one the watch ever looked at.
        limit = asyncio.Semaphore(self.BLOCKED_HOST_RESOLVE_CONCURRENCY)
        await asyncio.gather(*(self._resolve_blocked_host(entry, limit) for entry in entries))

        self._blocked_addresses = frozenset(
            address
            for addresses in self._blocked_addresses_by_host.values()
            for address in addresses
        )

    async def _watch_blocked_addresses(self) -> None:
        """Look the block list up again on a timer until the server stops."""
        while True:
            await asyncio.sleep(self.BLOCKED_HOST_RECHECK_SECONDS)
            try:
                await self.refresh_blocked_addresses()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                # A failed round must not take the watch down with it. The addresses
                # already held stay in force and the next round tries again.
                logger.warning("Could not re-resolve the blocked hosts", error=str(e))

    async def _resolve_allowed_address(
        self, host: str, port: int, username: Optional[str]
    ) -> Optional[list[str]]:
        """Resolve a host and return the addresses to connect to, or None if policy
        refuses it.

        The check has to run on what the name resolves to, not on the name: a client
        picks the name, and a name it controls can point at this machine's own loopback.
        The literals that come back are what the connect then uses, so a second lookup
        cannot answer differently. Any refused address refuses the whole name, because a
        reply mixing a public answer with a private one is the shape of a rebinding
        attempt rather than an ordinary host.

        Every allowed literal is returned, in the order the resolver gave them. Keeping
        only the first would make an unreachable family look like an unreachable host.
        """
        loop = asyncio.get_running_loop()
        resolved = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)

        allowed: list[str] = []
        for *_, sockaddr in resolved:
            # A scoped literal such as fe80::1%eth0 is not parseable, and everything
            # carrying a scope is link-local and refused below anyway
            literal = str(sockaddr[0]).split("%")[0]
            # A name the block list does not carry can still point at a blocked machine,
            # which is what an alias is. The address is what settles it.
            if self._is_blocked_address(literal):
                self._log_if_allowed(
                    "warning",
                    "Destination address belongs to a blocked host",
                    username=username,
                    host=host,
                    address=literal,
                )
                return None
            if not self._is_allowed_address(ip_address(literal)):
                self._log_if_allowed(
                    "warning",
                    "Destination address refused by policy",
                    username=username,
                    host=host,
                    address=literal,
                )
                return None
            if literal not in allowed:
                allowed.append(literal)
        return allowed

    async def _open_first_reachable(
        self, addresses: list[str], port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Connect to the first of these addresses that answers.

        Screening the destination means connecting to a literal rather than to the name,
        and a literal is one address out of however many the name carries. asyncio walks
        the list itself when it is handed a name, so stopping at the first address here
        would lose that: a dual-stack destination on a host with no route for the family
        the resolver happens to list first fails with Network is unreachable, for every
        such name, even though the other family works.
        """
        last_error: Optional[OSError] = None
        for address in addresses:
            try:
                return await asyncio.open_connection(address, port)
            except OSError as e:
                last_error = e

        if last_error is not None:
            raise last_error
        raise OSError(f"No address to connect to on port {port}")

    def _is_locked_out(self, source: str, username: str) -> bool:
        """Whether this source, or this account from a crowd of sources, has spent its
        attempts.

        The account-wide count exists because every fresh source address otherwise starts
        with a full budget against the same account, so guessing spread across addresses
        is unbounded. It is keyed by username alone, though, so on its own it is an
        off-switch for anybody whose username can be guessed: five wrong passwords and
        the real owner is refused before her own password is ever read. Two things stop it
        being that. It is given many times the budget one source gets, and a source that
        spends its own budget locks itself out, so reaching the account limit takes a
        crowd of addresses rather than one caller. And an address that has authenticated
        as this user before is never refused by it, so the person who knows the password
        keeps getting in while the crowd is counted against everyone else.
        """
        if self.max_failed_attempts <= 0:
            return False

        if self._spent_attempts(self._auth_failures, (source, username), self.max_failed_attempts):
            return True

        if self._authenticated_before(source, username):
            return False

        return self._spent_attempts(
            self._account_failures,
            username,
            self.max_failed_attempts * self.ACCOUNT_ATTEMPT_FACTOR,
        )

    def _spent_attempts[K](
        self,
        tracked: dict[K, LockoutState],
        key: K,
        limit: int,
    ) -> bool:
        """Whether this key is over the attempt limit and still inside the lockout window."""
        state = tracked.get(key)
        if state is None:
            return False

        if time.monotonic() - state.last_failure >= self._lockout_seconds:
            del tracked[key]
            return False

        return state.failures >= limit

    def _authenticated_before(self, source: str, username: str) -> bool:
        """Whether this source has authenticated as this user recently enough to trust."""
        key = (source, username)
        when = self._last_success.get(key)
        if when is None:
            return False

        if time.monotonic() - when >= self.KNOWN_SOURCE_TTL:
            del self._last_success[key]
            return False

        return True

    def _record_auth_success(self, source: str, username: str) -> None:
        """Clear this account's failures and remember that this source got in."""
        now = time.monotonic()
        self._auth_failures.pop((source, username), None)
        self._account_failures.pop(username, None)

        key = (source, username)
        if key not in self._last_success:
            _prune_tracking(
                self._last_success,
                lambda when: when,
                now - self.KNOWN_SOURCE_TTL,
                self.MAX_TRACKED_ENTRIES,
            )
        self._last_success[key] = now

    def _record_auth_failure(self, source: str, username: str) -> None:
        """Count one failed login against this source and username, and against the account."""
        now = time.monotonic()
        key = (source, username)

        state = self._auth_failures.get(key)
        if state is None:
            _prune_tracking(
                self._auth_failures,
                lambda entry: entry.last_failure,
                now - self._lockout_seconds,
                self.MAX_TRACKED_ENTRIES,
            )
            state = LockoutState()
            self._auth_failures[key] = state

        state.failures += 1
        state.last_failure = now

        # The count above throttles one source, which is not the same as protecting the
        # account: every fresh source address starts with a full budget against it, and
        # that map is capped, so a source can push its own entry out with invented
        # usernames and carry on. Counting real accounts too is what bounds guesses
        # against an account no matter how many addresses they arrive from.
        if self.auth_manager is None or self.auth_manager.get_user_info(username) is None:
            return

        account = self._account_failures.get(username)
        if account is None:
            account = LockoutState()
            self._account_failures[username] = account

        account.failures += 1
        account.last_failure = now

    def _rate_limit_exceeded(self, username: str, limit: int) -> bool:
        """Count one request for this user and report whether it went over their limit."""
        if limit <= 0:
            return False

        now = time.monotonic()
        state = self._user_requests.get(username)
        if state is None:
            _prune_tracking(
                self._user_requests,
                lambda entry: entry.window_start,
                now - self.RATE_LIMIT_WINDOW,
                self.MAX_TRACKED_ENTRIES,
            )
            state = RateLimitState()
            self._user_requests[username] = state

        if now - state.window_start >= self.RATE_LIMIT_WINDOW:
            state.window_start = now
            state.requests = 0

        state.requests += 1
        return state.requests > limit

    def set_connection_callback(
        self, callback: Callable[[ConnectionInfo], Awaitable[None]]
    ) -> None:
        """Set callback for new connections."""
        self._on_connection = callback

    @property
    def active_connections(self) -> int:
        """Get number of active connections."""
        return len(self._connections)

    @property
    def started_at(self) -> Optional[datetime]:
        """When the server started accepting connections, or None while it is stopped."""
        return self._started_at
