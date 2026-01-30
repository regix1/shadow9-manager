"""
User management CRUD endpoints.

RESTful API for user operations following REST conventions:
- POST /users - Create user
- GET /users - List users
- GET /users/{username} - Get user
- PATCH /users/{username} - Update user
- DELETE /users/{username} - Delete user
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status

from ...schemas.common import SuccessResponse
from ...schemas.user import UserCreate, UserListResponse, UserResponse, UserUpdate
from ...services.user_service import UserService
from ..deps import get_current_admin, get_user_service


router = APIRouter(prefix="/users", tags=["users"])


# CREATE
@router.post(
    "",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new user",
    responses={
        201: {"description": "User created successfully"},
        400: {"description": "Invalid input or user already exists"},
        401: {"description": "Invalid API key"},
    }
)
async def create_user(
    user_data: UserCreate,
    service: UserService = Depends(get_user_service),
    _admin: str = Depends(get_current_admin)
) -> UserResponse:
    """
    Create a new user account.
    
    - **username**: Unique username (3-64 chars, alphanumeric/underscore/hyphen)
    - **password**: Strong password (min 12 chars, mixed case, digit, special)
    - **use_tor**: Route traffic through Tor (default: true)
    - **bridge_type**: Tor bridge type for censorship circumvention
    - **security_level**: Security/evasion level
    - **allowed_ports**: Restrict to specific ports (null = all)
    - **rate_limit**: Max requests per minute (null = server default)
    - **bind_port**: Custom bind port (null = shared port)
    - **logging_enabled**: Enable activity logging
    """
    try:
        return await service.create(user_data)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


# READ - List
@router.get(
    "",
    response_model=UserListResponse,
    summary="List all users",
    responses={
        200: {"description": "List of users"},
        401: {"description": "Invalid API key"},
    }
)
async def list_users(
    skip: int = Query(0, ge=0, description="Number of users to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum users to return"),
    enabled_only: bool = Query(False, description="Only return enabled users"),
    service: UserService = Depends(get_user_service),
    _admin: str = Depends(get_current_admin)
) -> UserListResponse:
    """
    List all registered users with pagination.
    """
    users = await service.list(skip=skip, limit=limit, enabled_only=enabled_only)
    total = await service.count()
    
    return UserListResponse(users=users, total=total)


# READ - Get
@router.get(
    "/{username}",
    response_model=UserResponse,
    summary="Get user by username",
    responses={
        200: {"description": "User details"},
        401: {"description": "Invalid API key"},
        404: {"description": "User not found"},
    }
)
async def get_user(
    username: str,
    service: UserService = Depends(get_user_service),
    _admin: str = Depends(get_current_admin)
) -> UserResponse:
    """
    Get detailed information about a specific user.
    """
    user = await service.get(username)
    
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User not found: {username}"
        )
    
    return user


# UPDATE
@router.patch(
    "/{username}",
    response_model=UserResponse,
    summary="Update user properties",
    responses={
        200: {"description": "User updated"},
        400: {"description": "Invalid input"},
        401: {"description": "Invalid API key"},
        404: {"description": "User not found"},
    }
)
async def update_user(
    username: str,
    user_data: UserUpdate,
    service: UserService = Depends(get_user_service),
    _admin: str = Depends(get_current_admin)
) -> UserResponse:
    """
    Update a user's properties (partial update).
    
    Only provided fields will be updated. All fields are optional.
    """
    try:
        user = await service.update(username, user_data)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User not found: {username}"
        )
    
    return user


# DELETE
@router.delete(
    "/{username}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a user",
    responses={
        204: {"description": "User deleted"},
        401: {"description": "Invalid API key"},
        404: {"description": "User not found"},
    }
)
async def delete_user(
    username: str,
    service: UserService = Depends(get_user_service),
    _admin: str = Depends(get_current_admin)
) -> None:
    """
    Delete a user account permanently.
    """
    deleted = await service.delete(username)
    
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User not found: {username}"
        )


# ACTIONS - Enable/Disable
@router.post(
    "/{username}/enable",
    response_model=SuccessResponse,
    summary="Enable a user",
    responses={
        200: {"description": "User enabled"},
        401: {"description": "Invalid API key"},
        404: {"description": "User not found"},
    }
)
async def enable_user(
    username: str,
    service: UserService = Depends(get_user_service),
    _admin: str = Depends(get_current_admin)
) -> SuccessResponse:
    """
    Enable a disabled user account.
    """
    enabled = await service.enable(username)
    
    if not enabled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User not found: {username}"
        )
    
    return SuccessResponse(message=f"User '{username}' enabled")


@router.post(
    "/{username}/disable",
    response_model=SuccessResponse,
    summary="Disable a user",
    responses={
        200: {"description": "User disabled"},
        401: {"description": "Invalid API key"},
        404: {"description": "User not found"},
    }
)
async def disable_user(
    username: str,
    service: UserService = Depends(get_user_service),
    _admin: str = Depends(get_current_admin)
) -> SuccessResponse:
    """
    Disable a user account (prevents authentication).
    """
    disabled = await service.disable(username)
    
    if not disabled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User not found: {username}"
        )
    
    return SuccessResponse(message=f"User '{username}' disabled")


# UTILITY - Generate credentials
@router.post(
    "/generate",
    response_model=dict,
    summary="Generate random credentials",
    responses={
        200: {"description": "Generated credentials"},
        401: {"description": "Invalid API key"},
    }
)
async def generate_credentials(
    service: UserService = Depends(get_user_service),
    _admin: str = Depends(get_current_admin)
) -> dict:
    """
    Generate secure random username and password.
    
    The generated credentials are not automatically created.
    Use POST /users to create the user with these credentials.
    """
    username, password = await service.generate_credentials()
    
    return {
        "username": username,
        "password": password,
        "note": "Use POST /users to create the user with these credentials"
    }
