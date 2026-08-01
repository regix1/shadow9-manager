"""
FastAPI dependency injection.

Provides dependencies for services, authentication, etc.
"""

import os
import secrets
from functools import lru_cache
from pathlib import Path
from typing import Optional

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

from ..auth import AuthManager, MissingMasterKey
from ..config import Config, get_project_root
from ..core.config import get_settings
from ..repositories.user_repository import UserRepository
from ..services.user_service import UserService


# API Key security
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def get_master_key() -> Optional[str]:
    """
    Resolve the credential-store master key from settings or the environment.

    Returns:
        The master key if one is configured, None otherwise.
    """
    settings = get_settings()
    return settings.master_key or os.getenv("SHADOW9_MASTER_KEY")


@lru_cache()
def get_user_repository() -> UserRepository:
    """Get the user repository singleton."""
    settings = get_settings()
    credentials_file = settings.get_credentials_file()

    # The same setting the proxy sizes its own hashing cap from, so the unit's MemoryMax
    # comment holds for both processes rather than only the one
    try:
        return UserRepository(
            credentials_file=credentials_file,
            master_key=get_master_key(),
            max_concurrent_hashes=settings.auth.max_concurrent_auth,
            tunnel_network=settings.wireguard.tunnel_network,
        )
    except MissingMasterKey as missing:
        # The store refuses to open rather than keeping users as plain JSON. Answering
        # 503 says the service is not configured yet, which is the truth, and the path
        # to the credentials file stays out of the response.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Credential store unavailable: no master key is configured. "
                "Set SHADOW9_MASTER_KEY."
            ),
        ) from missing


def get_config() -> Config:
    """
    Load the dataclass configuration the WireGuard services read.

    The same file `get_settings` reads, loaded through the other half of the config pair,
    which is the half that hands out plain dataclasses rather than pydantic settings.

    Returns:
        The configuration, with environment overrides applied
    """
    selected = os.getenv("SHADOW9_CONFIG")
    config_file = (
        Path(selected).expanduser()
        if selected
        else get_project_root() / "config" / "config.yaml"
    )
    return Config.load(config_file if config_file.exists() else None)


def get_user_service(
    repository: UserRepository = Depends(get_user_repository),
    config: Config = Depends(get_config),
) -> UserService:
    """Get user service with repository injected."""
    return UserService(repository=repository, config=config)


def get_auth_manager(repository: UserRepository = Depends(get_user_repository)) -> AuthManager:
    """
    Get the credential store the API already holds.

    Handed out rather than built again, because a second store in the same process keeps
    its own copy of the credential table and the two of them go out of step the moment one
    writes. This process is meant to have exactly one.

    Returns:
        The store behind the user repository
    """
    return repository.auth_manager


async def verify_api_key(api_key: Optional[str] = Security(api_key_header)) -> str:
    """
    Verify API key for admin endpoints.

    The API key should match the SHADOW9_API_KEY environment variable.
    """
    expected_key = os.getenv("SHADOW9_API_KEY")

    if expected_key is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API key not configured. Set SHADOW9_API_KEY environment variable.",
        )

    # compare_digest rejects non-ASCII str, and Starlette decodes headers as latin-1,
    # so a header byte above 0x7F would raise TypeError and answer 500 instead of 401
    if api_key is None or not secrets.compare_digest(api_key.encode(), expected_key.encode()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing API key"
        )

    return api_key


# Alias for clarity
get_current_admin = verify_api_key
