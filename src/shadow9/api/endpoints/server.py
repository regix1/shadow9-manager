"""
Server management endpoints.

RESTful API for server status and control.
"""

from fastapi import APIRouter, Depends

from ...core.config import get_settings, Settings
from ...schemas.server import ServerStatusResponse
from ...services.user_service import UserService
from ..deps import get_current_admin, get_user_service


router = APIRouter(prefix="/server", tags=["server"])


@router.get(
    "/status",
    response_model=ServerStatusResponse,
    summary="Get server status",
    responses={
        200: {"description": "Server status information"},
        401: {"description": "Invalid API key"},
    }
)
async def get_server_status(
    settings: Settings = Depends(get_settings),
    user_service: UserService = Depends(get_user_service),
    _admin: str = Depends(get_current_admin)
) -> ServerStatusResponse:
    """
    Get current server status and statistics.
    """
    total_users = await user_service.count()
    
    return ServerStatusResponse(
        running=True,  # If API is responding, server is running
        host=settings.server.host,
        port=settings.server.port,
        active_connections=0,  # Would need server state integration
        total_users=total_users,
        tor_enabled=settings.tor.enabled,
        uptime_seconds=None,  # Would need server state integration
    )


@router.get(
    "/config",
    summary="Get server configuration",
    responses={
        200: {"description": "Server configuration"},
        401: {"description": "Invalid API key"},
    }
)
async def get_server_config(
    settings: Settings = Depends(get_settings),
    _admin: str = Depends(get_current_admin)
) -> dict:
    """
    Get current server configuration (non-sensitive values).
    """
    return {
        "server": {
            "host": settings.server.host,
            "port": settings.server.port,
            "max_connections": settings.server.max_connections,
            "connection_timeout": settings.server.connection_timeout,
        },
        "tor": {
            "enabled": settings.tor.enabled,
            "socks_port": settings.tor.socks_port,
        },
        "auth": {
            "require_auth": settings.auth.require_auth,
            "max_failed_attempts": settings.auth.max_failed_attempts,
            "lockout_duration": settings.auth.lockout_duration,
        },
        "security": {
            "allowed_ports": settings.security.allowed_ports,
            "default_rate_limit": settings.security.default_rate_limit,
            "block_private_ranges": settings.security.block_private_ranges,
        },
        "log": {
            "level": settings.log.level,
            "format": settings.log.format,
        }
    }
