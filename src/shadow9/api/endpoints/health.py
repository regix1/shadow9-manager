"""
Health check endpoints.
"""

from fastapi import APIRouter, Depends

from ..deps import get_current_admin

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
@router.get("/")
async def health_check(
    _admin: str = Depends(get_current_admin)
) -> dict:
    """
    Health check endpoint.
    
    Returns basic service status.
    """
    return {
        "status": "healthy",
        "service": "shadow9-manager"
    }


@router.get("/ready")
async def readiness_check(
    _admin: str = Depends(get_current_admin)
) -> dict:
    """
    Readiness check endpoint.
    
    Returns whether the service is ready to accept requests.
    """
    return {
        "status": "ready",
        "service": "shadow9-manager"
    }
