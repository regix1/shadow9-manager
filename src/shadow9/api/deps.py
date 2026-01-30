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

from ..core.config import Settings, get_settings
from ..repositories.user_repository import UserRepository
from ..services.auth_service import AuthService
from ..services.user_service import UserService


# API Key security
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


@lru_cache()
def get_user_repository() -> UserRepository:
    """Get the user repository singleton."""
    settings = get_settings()
    credentials_file = settings.get_credentials_file()
    master_key = settings.master_key or os.getenv("SHADOW9_MASTER_KEY")
    
    return UserRepository(
        credentials_file=credentials_file,
        master_key=master_key
    )


def get_user_service(
    repository: UserRepository = Depends(get_user_repository)
) -> UserService:
    """Get user service with repository injected."""
    return UserService(repository=repository)


def get_auth_service(
    repository: UserRepository = Depends(get_user_repository)
) -> AuthService:
    """Get auth service with repository injected."""
    return AuthService(repository=repository)


async def verify_api_key(
    api_key: Optional[str] = Security(api_key_header),
    settings: Settings = Depends(get_settings)
) -> str:
    """
    Verify API key for admin endpoints.
    
    The API key should match the SHADOW9_API_KEY environment variable.
    """
    expected_key = os.getenv("SHADOW9_API_KEY")
    
    if expected_key is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API key not configured. Set SHADOW9_API_KEY environment variable."
        )
    
    if api_key is None or not secrets.compare_digest(api_key, expected_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key"
        )
    
    return api_key


# Alias for clarity
get_current_admin = verify_api_key
