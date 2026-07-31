"""
Common API schemas used across endpoints.
"""

from typing import Any, Optional

from pydantic import BaseModel, Field


class SuccessResponse(BaseModel):
    """Generic success response."""

    success: bool = Field(default=True)
    message: str = Field(..., description="Success message")
    data: Optional[Any] = Field(default=None, description="Optional response data")


class ErrorResponse(BaseModel):
    """Error response schema."""

    success: bool = Field(default=False)
    error: str = Field(..., description="Error type/code")
    message: str = Field(..., description="Human-readable error message")
    details: Optional[dict] = Field(default=None, description="Additional error details")


class PaginationParams(BaseModel):
    """Pagination parameters for list endpoints."""

    skip: int = Field(default=0, ge=0, description="Number of items to skip")
    limit: int = Field(default=100, ge=1, le=1000, description="Maximum items to return")


