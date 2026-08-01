"""
Tests for Pydantic domain models.
"""

import pytest
from datetime import datetime, timedelta, timezone, UTC
from pydantic import ValidationError

from shadow9.auth import Credential as StoredCredential
from shadow9.models.user import (
    SecurityLevel,
    BridgeType,
    PeerRole,
    UserBase,
    User,
    Credential,
    utc_now,
)
from shadow9.wireguard.keys import generate_keypair
from shadow9.models.server import (
    Socks5AuthMethod,
    Socks5Command,
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
            created_at=utc_now(),
        )
        assert user.created_at is not None
        assert user.last_used is None

    def test_credential_model(self):
        """Test Credential model."""
        now = utc_now()
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

    def test_credential_to_dict_writes_the_stored_timestamp_shape(self):
        """A zone-aware time is written the way the credentials file already holds it."""
        cred = Credential(
            username="test_user",
            password_hash="hash123",
            created_at=datetime(2024, 1, 15, 10, 30, tzinfo=UTC),
        )
        data = cred.to_dict()

        assert data["created_at"] == "2024-01-15T10:30:00"
        assert Credential.from_dict(dict(data)).created_at == cred.created_at

    def test_credential_from_dict_reads_a_stored_timestamp_as_utc(self):
        """A stored timestamp carries no offset, and has always meant UTC."""
        cred = Credential.from_dict(
            {
                "username": "test_user",
                "password_hash": "hash123",
                "created_at": "2024-01-15T10:30:00",
            }
        )

        assert cred.created_at == datetime(2024, 1, 15, 10, 30, tzinfo=UTC)


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


class TestPeerSettingsOnTheUserModel:
    """The model and the credential store hold the same seven fields, checked the same way."""

    def test_a_user_is_not_a_peer_until_the_fields_are_set(self):
        user = UserBase(username="alice")

        assert user.wg_public_key is None
        assert user.wg_address is None
        assert user.wg_routes is None
        assert user.wg_role is None
        assert user.wg_endpoint is None
        assert user.wg_keepalive is None
        assert user.wg_expires_at is None

    def test_a_peer_keeps_what_it_was_given(self):
        keypair = generate_keypair()
        user = UserBase(
            username="gateway",
            wg_public_key=keypair.public_key,
            wg_address="10.9.0.2",
            wg_routes=["192.168.1.0/24", "10.0.0.0/8"],
            wg_role=PeerRole.NODE,
            wg_endpoint="203.0.113.10:51820",
            wg_keepalive=25,
        )

        assert user.wg_public_key == keypair.public_key
        assert user.wg_routes == ["192.168.1.0/24", "10.0.0.0/8"]
        assert user.wg_role is PeerRole.NODE

    def test_a_key_the_tunnel_would_reject_is_refused(self):
        with pytest.raises(ValidationError):
            UserBase(username="alice", wg_public_key="not-a-key")

    def test_a_key_of_the_right_length_that_is_not_base64_is_refused(self):
        """44 characters is not the check. Decoding to 32 bytes is."""
        with pytest.raises(ValidationError):
            UserBase(username="alice", wg_public_key="!" * 44)

    def test_an_address_written_as_a_range_is_refused(self):
        with pytest.raises(ValidationError):
            UserBase(username="alice", wg_address="10.9.0.2/24")

    def test_a_route_carrying_host_bits_is_refused_rather_than_masked_off(self):
        with pytest.raises(ValidationError):
            UserBase(username="alice", wg_routes=["192.168.1.1/24"])

    def test_a_route_that_is_not_a_network_is_refused(self):
        with pytest.raises(ValidationError):
            UserBase(username="alice", wg_routes=["everything"])

    def test_a_role_that_is_not_one_of_the_three_is_refused(self):
        with pytest.raises(ValidationError):
            UserBase(username="alice", wg_role="gateway")

    def test_a_keepalive_outside_the_range_is_refused(self):
        with pytest.raises(ValidationError):
            UserBase(username="alice", wg_keepalive=0)
        with pytest.raises(ValidationError):
            UserBase(username="alice", wg_keepalive=70000)

    def test_an_empty_endpoint_is_refused(self):
        with pytest.raises(ValidationError):
            UserBase(username="alice", wg_endpoint="   ")

    def test_a_peer_reaches_the_store_in_the_shapes_the_store_holds(self):
        """to_dict feeds the dataclass the store writes, and json.dumps is what is under it.

        Left as a PeerRole and a datetime these two would reach the file's json.dumps and
        fail the write there, which is a long way from the model that produced them.
        """
        keypair = generate_keypair()
        credential = Credential(
            username="gateway",
            password_hash="hash",
            wg_public_key=keypair.public_key,
            wg_address="10.9.0.2",
            wg_routes=["192.168.1.0/24"],
            wg_role=PeerRole.NODE,
            wg_endpoint="203.0.113.10:51820",
            wg_keepalive=25,
            wg_expires_at=datetime(2027, 1, 1, 13, 0, tzinfo=timezone(timedelta(hours=2))),
        )

        data = credential.to_dict()

        assert data["wg_role"] == "node"
        assert data["wg_expires_at"] == "2027-01-01T11:00:00"
        assert isinstance(data["wg_routes"], list)

        stored = StoredCredential(**data)
        assert stored.wg_public_key == keypair.public_key
        assert stored.wg_role == "node"
        assert stored.wg_expires_at == "2027-01-01T11:00:00"

    def test_a_stored_peer_reads_back_into_the_model(self):
        keypair = generate_keypair()
        credential = Credential.from_dict(
            {
                "username": "gateway",
                "password_hash": "hash",
                "created_at": "2026-01-01T00:00:00",
                "wg_public_key": keypair.public_key,
                "wg_address": "10.9.0.2",
                "wg_routes": ["192.168.1.0/24"],
                "wg_role": "node",
                "wg_endpoint": "203.0.113.10:51820",
                "wg_keepalive": 25,
                "wg_expires_at": "2027-01-01T00:00:00",
            }
        )

        assert credential.wg_role is PeerRole.NODE
        assert credential.wg_expires_at == datetime(2027, 1, 1, tzinfo=UTC)
        assert credential.wg_address == "10.9.0.2"

    def test_a_user_who_is_not_a_peer_round_trips_with_no_peer_settings(self):
        credential = Credential(username="alice", password_hash="hash")

        stored = StoredCredential(**credential.to_dict())

        assert stored.wg_public_key is None
        assert stored.wg_routes is None
        assert stored.wg_expires_at is None
