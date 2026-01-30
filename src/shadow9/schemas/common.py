"""
Common API schemas used across endpoints.
"""

from typing import Any, Generic, Optional, TypeVar

from pydantic import BaseModel, Field


T = TypeVar("T")


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


class PaginatedResponse(BaseModel, Generic[T]):
    """Paginated response wrapper."""
    items: list[T] = Field(..., description="List of items")
    total: int = Field(..., ge=0, description="Total number of items")
    skip: int = Field(..., ge=0, description="Items skipped")
    limit: int = Field(..., ge=1, description="Maximum items returned")
    
    @property
    def has_more(self) -> bool:
        """Check if there are more items."""
        return self.skip + len(self.items) < self.total
