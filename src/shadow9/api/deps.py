"""
FastAPI dependency injection.

Provides dependencies for services, authentication, etc.
"""

import os
import secrets
from functools import lru_cache
from typing import Optional

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

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
    return UserRepository(
        credentials_file=credentials_file,
        master_key=get_master_key(),
        max_concurrent_hashes=settings.auth.max_concurrent_auth,
    )


def get_user_service(repository: UserRepository = Depends(get_user_repository)) -> UserService:
    """Get user service with repository injected."""
    return UserService(repository=repository)


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
