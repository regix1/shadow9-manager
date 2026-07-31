"""
Health check endpoints.
"""

from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

from ...core.logging import get_logger
from ..deps import get_master_key, get_user_repository

logger = get_logger(__name__)

router = APIRouter(prefix="/health", tags=["health"])


def _not_ready(reason: str) -> JSONResponse:
    """Build the readiness response for an instance that cannot serve requests."""
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "status": "not_ready",
            "service": "shadow9-manager",
            "reason": reason,
        },
    )


@router.get("")
@router.get("/")
async def health_check() -> dict:
    """
    Health check endpoint.

    Returns basic service status.
    """
    # a liveness probe behind auth cannot answer when auth is what broke
    return {"status": "healthy", "service": "shadow9-manager"}


@router.get("/ready")
async def readiness_check() -> JSONResponse:
    """
    Readiness check endpoint.

    Reports ready only when a master key is configured and the credential store
    actually loads, so an orchestrator does not send traffic to an instance that
    cannot answer a single user request.
    """
    if not get_master_key():
        logger.warning("Readiness check failed: no master key configured")
        return _not_ready("master key not configured")

    try:
        repository = get_user_repository()
        # Called for what it proves, not for the number: reading the store is the thing
        # readiness is asking about. The count itself stays out of the response, because
        # this endpoint answers without credentials and how many customers an instance
        # holds is not something an unauthenticated caller needs to be told.
        await repository.count()
    except Exception as e:
        logger.warning("Readiness check failed: credential store unreadable", error=str(e))
        return _not_ready("credential store could not be read")

    # A file that will not decrypt does not raise here: the store keeps whatever it had
    # in memory and answers with that count, which on a cold start is zero and reads
    # exactly like a fresh install. Serving on that basis lets a later write replace the
    # damaged file with an empty one.
    if repository.load_error:
        logger.warning(
            "Readiness check failed: credential store unreadable", error=repository.load_error
        )
        return _not_ready("credential store could not be read")

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "status": "ready",
            "service": "shadow9-manager",
        },
    )
