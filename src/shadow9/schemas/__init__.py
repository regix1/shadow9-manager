"""
Shadow9 API Schemas

Request and response schemas for the REST API.
These are separate from domain models to control what is exposed.
"""

from .user import (
    UserCreate,
    UserUpdate,
    UserResponse,
    UserListResponse,
)
from .server import (
    ServerStatusResponse,
    ServerConfigUpdate,
)
from .common import (
    SuccessResponse,
    ErrorResponse,
    PaginationParams,
)

__all__ = [
    # User schemas
    "UserCreate",
    "UserUpdate", 
    "UserResponse",
    "UserListResponse",
    # Server schemas
    "ServerStatusResponse",
    "ServerConfigUpdate",
    # Common schemas
    "SuccessResponse",
    "ErrorResponse",
    "PaginationParams",
]
