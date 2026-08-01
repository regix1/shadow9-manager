"""TCP listener checks shared by CLI and API status reports."""

import asyncio

from ..core.logging import get_logger


logger = get_logger(__name__)

# A status probe must answer quickly even when the configured host drops packets.
PROBE_TIMEOUT = 1.0


async def _something_is_listening(host: str, port: int) -> bool:
    """Return whether a TCP connection is accepted at the configured address."""
    probe_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host

    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(probe_host, port), timeout=PROBE_TIMEOUT
        )
    except (OSError, asyncio.TimeoutError) as error:
        logger.debug(
            "Configured service did not accept a probe connection",
            host=probe_host,
            port=port,
            error=str(error),
        )
        return False

    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=PROBE_TIMEOUT)
    except (OSError, asyncio.TimeoutError):
        pass
    return True
