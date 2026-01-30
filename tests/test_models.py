"""
Tests for Pydantic domain models.
"""

import pytest
from datetime import datetime
from pydantic import ValidationError

from shadow9.models.user import (
    SecurityLevel,
    BridgeType,
    UserBase,
    User,
    Credential,
)
from shadow9.models.server import (
    Socks5AuthMethod,
    Socks5Command,
    Socks5AddressType,
    Socks5Reply,
    ConnectionInfo,
    ServerStatus,
)


class TestUserModels:
    """Tests for user-related models."""

    def test_security_level_enum(self):
        """Test SecurityLevel enum values."""
        assert SecurityLevel.NONE == "none"
        assert SecurityLevel.BASIC == "basic"
        assert SecurityLevel.MODERATE == "moderate"
        assert SecurityLevel.PARANOID == "paranoid"

    def test_bridge_type_enum(self):
        """Test BridgeType enum values."""
        assert BridgeType.NONE == "none"
        assert BridgeType.OBFS4 == "obfs4"
        assert BridgeType.SNOWFLAKE == "snowflake"

    def test_user_base_valid(self):
        """Test valid UserBase creation."""
        user = UserBase(
            username="test_user",
            use_tor=True,
            bridge_type=BridgeType.OBFS4,
            security_level=SecurityLevel.MODERATE,
        )
        assert user.username == "test_user"
        assert user.use_tor is True
        assert user.bridge_type == BridgeType.OBFS4
        assert user.security_level == SecurityLevel.MODERATE

    def test_user_base_defaults(self):
        """Test UserBase default values."""
        user = UserBase(username="test_user")
        assert user.use_tor is True
        assert user.bridge_type == BridgeType.NONE
        assert user.security_level == SecurityLevel.BASIC
        assert user.allowed_ports is None
        assert user.rate_limit is None
        assert user.bind_port is None
        assert user.logging_enabled is True
        assert user.enabled is True

    def test_user_base_username_validation(self):
        """Test username validation rules."""
        # Too short
        with pytest.raises(ValidationError):
            UserBase(username="ab")
        
        # Too long
        with pytest.raises(ValidationError):
            UserBase(username="a" * 65)
        
        # Invalid characters
        with pytest.raises(ValidationError):
            UserBase(username="user@name")
        
        # Valid usernames
        UserBase(username="abc")  # minimum length
        UserBase(username="user_name")
        UserBase(username="user-name")
        UserBase(username="user123")

    def test_user_base_port_validation(self):
        """Test port field validation."""
        # Invalid bind port
        with pytest.raises(ValidationError):
            UserBase(username="test", bind_port=0)
        
        with pytest.raises(ValidationError):
            UserBase(username="test", bind_port=70000)
        
        # Valid bind port
        user = UserBase(username="test", bind_port=8080)
        assert user.bind_port == 8080

    def test_user_base_allowed_ports_validation(self):
        """Test allowed_ports validation."""
        # Invalid port in list
        with pytest.raises(ValidationError):
            UserBase(username="test", allowed_ports=[80, 70000])
        
        # Valid ports
        user = UserBase(username="test", allowed_ports=[80, 443, 8080])
        assert user.allowed_ports == [80, 443, 8080]

    def test_user_model(self):
        """Test User model with timestamps."""
        user = User(
            username="test_user",
            created_at=datetime.utcnow(),
        )
        assert user.created_at is not None
        assert user.last_used is None

    def test_credential_model(self):
        """Test Credential model."""
        now = datetime.utcnow()
        cred = Credential(
            username="test_user",
            password_hash="$argon2id$v=19$...",
            created_at=now,
        )
        assert cred.password_hash == "$argon2id$v=19$..."
        assert cred.created_at == now

    def test_credential_to_dict(self):
        """Test Credential serialization."""
        cred = Credential(
            username="test_user",
            password_hash="hash123",
            use_tor=True,
            bridge_type=BridgeType.OBFS4,
            security_level=SecurityLevel.PARANOID,
        )
        data = cred.to_dict()
        
        assert data["username"] == "test_user"
        assert data["password_hash"] == "hash123"
        assert data["bridge_type"] == "obfs4"
        assert data["security_level"] == "paranoid"

    def test_credential_from_dict(self):
        """Test Credential deserialization."""
        data = {
            "username": "test_user",
            "password_hash": "hash123",
            "use_tor": True,
            "bridge_type": "obfs4",
            "security_level": "paranoid",
            "created_at": "2024-01-15T10:30:00",
        }
        cred = Credential.from_dict(data)
        
        assert cred.username == "test_user"
        assert cred.bridge_type == BridgeType.OBFS4
        assert cred.created_at.year == 2024


class TestServerModels:
    """Tests for server-related models."""

    def test_socks5_auth_method(self):
        """Test Socks5AuthMethod enum."""
        assert Socks5AuthMethod.NO_AUTH == 0x00
        assert Socks5AuthMethod.USERNAME_PASSWORD == 0x02
        assert Socks5AuthMethod.NO_ACCEPTABLE == 0xFF

    def test_socks5_command(self):
        """Test Socks5Command enum."""
        assert Socks5Command.CONNECT == 0x01
        assert Socks5Command.BIND == 0x02
        assert Socks5Command.UDP_ASSOCIATE == 0x03

    def test_socks5_reply(self):
        """Test Socks5Reply enum."""
        assert Socks5Reply.SUCCEEDED == 0x00
        assert Socks5Reply.CONNECTION_REFUSED == 0x05

    def test_connection_info(self):
        """Test ConnectionInfo model."""
        info = ConnectionInfo(
            client_address="192.168.1.100",
            client_port=54321,
            username="test_user",
            target_host="example.com",
            target_port=443,
            use_tor=True,
        )
        assert info.client_address == "192.168.1.100"
        assert info.use_tor is True
        assert info.bytes_sent == 0

    def test_server_status(self):
        """Test ServerStatus model."""
        status = ServerStatus(
            running=True,
            host="127.0.0.1",
            port=1080,
            active_connections=5,
            total_users=10,
            tor_enabled=True,
        )
        assert status.running is True
        assert status.active_connections == 5
