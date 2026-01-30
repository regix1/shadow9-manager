"""
Tests for API request/response schemas.
"""

import pytest
from datetime import datetime
from pydantic import ValidationError

from shadow9.schemas.user import UserCreate, UserUpdate, UserResponse
from shadow9.schemas.common import SuccessResponse, ErrorResponse, PaginationParams
from shadow9.models.user import BridgeType, SecurityLevel


class TestUserSchemas:
    """Tests for user API schemas."""

    def test_user_create_valid(self):
        """Test valid UserCreate schema."""
        data = UserCreate(
            username="test_user",
            password="SecurePass123!",
            use_tor=True,
        )
        assert data.username == "test_user"
        assert data.password == "SecurePass123!"

    def test_user_create_password_validation(self):
        """Test password strength validation."""
        # Too short
        with pytest.raises(ValidationError) as exc_info:
            UserCreate(username="test", password="Short1!")
        assert "at least 12 characters" in str(exc_info.value)
        
        # No uppercase
        with pytest.raises(ValidationError) as exc_info:
            UserCreate(username="test", password="password123!!")
        assert "uppercase" in str(exc_info.value)
        
        # No lowercase
        with pytest.raises(ValidationError) as exc_info:
            UserCreate(username="test", password="PASSWORD123!!")
        assert "lowercase" in str(exc_info.value)
        
        # No digit
        with pytest.raises(ValidationError) as exc_info:
            UserCreate(username="test", password="PasswordOnly!!")
        assert "digit" in str(exc_info.value)
        
        # No special character
        with pytest.raises(ValidationError) as exc_info:
            UserCreate(username="test", password="Password12345")
        assert "special" in str(exc_info.value)

    def test_user_create_with_all_fields(self):
        """Test UserCreate with all optional fields."""
        data = UserCreate(
            username="test_user",
            password="SecurePass123!",
            use_tor=True,
            bridge_type=BridgeType.OBFS4,
            security_level=SecurityLevel.PARANOID,
            allowed_ports=[80, 443],
            rate_limit=50,
            bind_port=9000,
            logging_enabled=False,
        )
        assert data.bridge_type == BridgeType.OBFS4
        assert data.security_level == SecurityLevel.PARANOID
        assert data.allowed_ports == [80, 443]
        assert data.rate_limit == 50
        assert data.bind_port == 9000
        assert data.logging_enabled is False

    def test_user_update_partial(self):
        """Test partial update schema."""
        # Only update use_tor
        data = UserUpdate(use_tor=False)
        assert data.use_tor is False
        assert data.password is None
        assert data.bridge_type is None
        
        # Update multiple fields
        data = UserUpdate(
            bridge_type=BridgeType.SNOWFLAKE,
            enabled=False,
        )
        assert data.bridge_type == BridgeType.SNOWFLAKE
        assert data.enabled is False

    def test_user_update_password_validation(self):
        """Test password validation on update."""
        # Valid password
        data = UserUpdate(password="NewSecurePass123!")
        assert data.password == "NewSecurePass123!"
        
        # Invalid password
        with pytest.raises(ValidationError):
            UserUpdate(password="weak")

    def test_user_response(self):
        """Test UserResponse schema."""
        response = UserResponse(
            username="test_user",
            use_tor=True,
            bridge_type=BridgeType.NONE,
            security_level=SecurityLevel.BASIC,
            allowed_ports=None,
            rate_limit=None,
            bind_port=None,
            logging_enabled=True,
            enabled=True,
            created_at=datetime.utcnow(),
            last_used=None,
        )
        assert response.username == "test_user"
        assert response.enabled is True


class TestCommonSchemas:
    """Tests for common API schemas."""

    def test_success_response(self):
        """Test SuccessResponse schema."""
        response = SuccessResponse(message="Operation completed")
        assert response.success is True
        assert response.message == "Operation completed"
        assert response.data is None

    def test_success_response_with_data(self):
        """Test SuccessResponse with data."""
        response = SuccessResponse(
            message="User created",
            data={"id": 123}
        )
        assert response.data == {"id": 123}

    def test_error_response(self):
        """Test ErrorResponse schema."""
        response = ErrorResponse(
            error="NOT_FOUND",
            message="User not found"
        )
        assert response.success is False
        assert response.error == "NOT_FOUND"

    def test_pagination_params_defaults(self):
        """Test PaginationParams defaults."""
        params = PaginationParams()
        assert params.skip == 0
        assert params.limit == 100

    def test_pagination_params_validation(self):
        """Test PaginationParams validation."""
        # Negative skip
        with pytest.raises(ValidationError):
            PaginationParams(skip=-1)
        
        # Zero limit
        with pytest.raises(ValidationError):
            PaginationParams(limit=0)
        
        # Limit too high
        with pytest.raises(ValidationError):
            PaginationParams(limit=5000)
