"""
Tests for the FastAPI REST API endpoints.
"""

import importlib
import os
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, UTC
from typing import Optional

from fastapi.testclient import TestClient

from shadow9.api.app import create_app
from shadow9.api.deps import get_user_repository
from shadow9.config import Config
from shadow9.core.api_config import get_api_key, set_api_key
from shadow9.core.config import get_settings, Settings
from shadow9.models.user import BridgeType, Credential, SecurityLevel
from shadow9.repositories.user_repository import UserRepository
from shadow9.schemas.user import UserCreate, UserUpdate
from shadow9.services.user_service import UserService
from shadow9.services import user_service as user_service_module


def _utc_now() -> datetime:
    """The naive UTC time the credential model's own default produces.

    datetime.utcnow() is deprecated. The timezone-aware call that replaces it renders a
    "+00:00" offset that the model does not, so a record built here with one would be a
    shape the application never writes.
    """
    return datetime.now(UTC).replace(tzinfo=None)


class TestListenerLaunch:
    """The API start command starts the admin and enrollment listeners together."""

    def test_start_passes_both_listener_addresses_to_the_server(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from shadow9.api import app as app_module
        from shadow9.commands import api as api_commands

        listener_config = Config()
        listener_config.wireguard.enrollment_host = "0.0.0.0"
        listener_config.wireguard.enrollment_port = 8191
        called: dict[str, object] = {}

        def read_api_config(_config_path: str) -> dict[str, object]:
            return {"host": "127.0.0.1", "port": 8090}

        def no_api_key(_config_path: Path) -> None:
            return None

        def load_config(_cls: type[Config], _config_path: Path | None = None) -> Config:
            return listener_config

        def config_dir() -> Path:
            return Path("config")

        def docs_are_off() -> bool:
            return False

        def run_servers(
            host: str,
            port: int,
            reload: bool,
            enrollment_host: str,
            enrollment_port: int,
            socks_port: int,
        ) -> None:
            called.update(
                host=host,
                port=port,
                reload=reload,
                enrollment_host=enrollment_host,
                enrollment_port=enrollment_port,
                socks_port=socks_port,
            )

        monkeypatch.setattr(api_commands, "_read_api_config", read_api_config)
        monkeypatch.setattr(api_commands, "get_api_key", no_api_key)
        monkeypatch.setattr(api_commands.Config, "load", classmethod(load_config))
        monkeypatch.setattr(api_commands, "get_config_dir", config_dir)
        monkeypatch.setattr(api_commands, "_docs_are_published", docs_are_off)
        monkeypatch.setattr(app_module, "run_server", run_servers)

        api_commands._start_impl("api.yaml", None, None, False)

        assert called == {
            "host": "127.0.0.1",
            "port": 8090,
            "reload": False,
            "enrollment_host": "0.0.0.0",
            "enrollment_port": 8191,
            "socks_port": 1080,
        }

    @pytest.mark.parametrize(
        ("left", "right", "ports"),
        [
            (
                "api.port",
                "wireguard.enrollment_port",
                {"port": 8081, "enrollment_port": 8081, "socks_port": 1080},
            ),
            (
                "api.port",
                "server.port",
                {"port": 1080, "enrollment_port": 8081, "socks_port": 1080},
            ),
            (
                "wireguard.enrollment_port",
                "server.port",
                {"port": 8080, "enrollment_port": 1080, "socks_port": 1080},
            ),
        ],
    )
    def test_server_refuses_two_listeners_on_one_port(
        self, left: str, right: str, ports: dict[str, int]
    ) -> None:
        from shadow9.api.app import run_server

        with pytest.raises(ValueError) as raised:
            run_server(**ports)

        message = str(raised.value)
        assert left in message
        assert right in message


# Create test app
app = create_app()


@contextmanager
def overridden_repository(repository: object) -> Iterator[None]:
    """
    Put a stand-in repository behind the routes for the body of the `with`.

    Patching the module attribute does nothing here: `Depends` captures the function
    object when the route is declared, and `get_user_repository` is cached on top of
    that, so a test that patches the name still reaches the real credential store on
    whatever machine it runs on.
    """
    app.dependency_overrides[get_user_repository] = lambda: repository
    try:
        yield
    finally:
        app.dependency_overrides.pop(get_user_repository, None)


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def api_key():
    """Provide test API key."""
    return "test-api-key"


@pytest.fixture
def auth_headers(api_key):
    """Provide authentication headers."""
    return {"X-API-Key": api_key}


class TestHealthEndpoints:
    """Tests for health check endpoints."""

    def test_health_check(self, client):
        """Test basic health check."""
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "shadow9-manager"

    def test_wireguard_enrollment_is_not_served(self, client: TestClient) -> None:
        response = client.post("/api/wireguard/enroll", json={})

        assert response.status_code == 404

    @patch.dict("os.environ", {"SHADOW9_API_KEY": "test-api-key"})
    def test_admin_routes_remain_mounted(self, client: TestClient) -> None:
        assert client.get("/api/health").status_code == 200
        assert client.get("/api/users").status_code == 401
        assert client.get("/api/server/config").status_code == 401

    @patch.dict("os.environ", {"SHADOW9_MASTER_KEY": "test-master-key"})
    @patch("shadow9.api.endpoints.health.get_user_repository")
    def test_readiness_check(self, mock_repo, client):
        """Test readiness check."""
        mock_repo_instance = MagicMock()
        mock_repo_instance.count = AsyncMock(return_value=3)
        mock_repo_instance.load_error = None
        mock_repo.return_value = mock_repo_instance

        response = client.get("/api/health/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"
        # The endpoint answers without credentials, so how many users this instance
        # holds must not be in the body
        assert "users_loaded" not in data

    @patch.dict("os.environ", {"SHADOW9_MASTER_KEY": "test-master-key"})
    @patch("shadow9.api.endpoints.health.get_user_repository")
    def test_readiness_check_fails_when_the_store_will_not_decrypt(self, mock_repo, client):
        """A file that will not decrypt reads as an empty store, which must not report ready.

        Nothing raises: the store keeps its in-memory table, which on a cold start is
        empty, so the count alone cannot tell a damaged file from a fresh install.
        """
        mock_repo_instance = MagicMock()
        mock_repo_instance.count = AsyncMock(return_value=0)
        mock_repo_instance.load_error = "InvalidToken"
        mock_repo.return_value = mock_repo_instance

        response = client.get("/api/health/ready")
        assert response.status_code == 503
        assert response.json()["status"] == "not_ready"

    @patch("shadow9.api.endpoints.health.get_master_key", return_value=None)
    def test_readiness_check_fails_without_master_key(self, _mock_key, client):
        """A service with no master key cannot decrypt credentials, so it is not ready."""
        response = client.get("/api/health/ready")
        assert response.status_code == 503
        assert response.json()["status"] == "not_ready"

    @patch.dict("os.environ", {"SHADOW9_MASTER_KEY": "test-master-key"})
    @patch("shadow9.api.endpoints.health.get_user_repository")
    def test_readiness_check_fails_when_credential_store_unreadable(self, mock_repo, client):
        """A credential store that will not load means the service cannot serve users."""
        mock_repo.side_effect = ValueError("corrupt credentials file")

        response = client.get("/api/health/ready")
        assert response.status_code == 503
        assert response.json()["status"] == "not_ready"


class TestUserEndpoints:
    """Tests for user CRUD endpoints."""

    @patch.dict("os.environ", {"SHADOW9_API_KEY": "test-api-key"})
    def test_create_user_requires_auth(self, client):
        """Test that user creation requires API key."""
        # No API key
        response = client.post(
            "/api/users",
            json={
                "username": "test_user",
                "password": "SecurePass123!",
            },
        )
        assert response.status_code == 401

    @patch.dict("os.environ", {"SHADOW9_API_KEY": "test-api-key"})
    def test_create_user_success(self, client, auth_headers):
        """Test successful user creation."""
        repository = MagicMock()
        repository.hash_password.return_value = "hashed_password"
        repository.exists = AsyncMock(return_value=False)
        repository.create = AsyncMock(
            return_value=Credential(
                username="test_user",
                password_hash="hashed_password",
                use_tor=True,
                bridge_type=BridgeType.NONE,
                security_level=SecurityLevel.BASIC,
                logging_enabled=True,
                enabled=True,
                created_at=_utc_now(),
            )
        )

        with overridden_repository(repository):
            response = client.post(
                "/api/users",
                json={
                    "username": "test_user",
                    "password": "SecurePass123!",
                },
                headers=auth_headers,
            )

        assert response.status_code == 201, response.text
        assert response.json()["username"] == "test_user"
        repository.create.assert_awaited_once()

    @patch.dict("os.environ", {"SHADOW9_API_KEY": "test-api-key"})
    def test_create_user_validation_error(self, client, auth_headers):
        """Test user creation with invalid data."""
        # Invalid password (too weak)
        response = client.post(
            "/api/users",
            json={
                "username": "test_user",
                "password": "weak",
            },
            headers=auth_headers,
        )
        assert response.status_code == 422  # Validation error

    @patch.dict("os.environ", {"SHADOW9_API_KEY": "test-api-key"})
    def test_create_user_invalid_username(self, client, auth_headers):
        """Test user creation with invalid username."""
        response = client.post(
            "/api/users",
            json={
                "username": "a",  # Too short
                "password": "SecurePass123!",
            },
            headers=auth_headers,
        )
        assert response.status_code == 422

    @patch.dict("os.environ", {"SHADOW9_API_KEY": "test-api-key"})
    def test_list_users(self, client, auth_headers):
        """Test user listing."""
        repository = MagicMock()
        repository.list = AsyncMock(return_value=[])
        repository.count = AsyncMock(return_value=0)

        with overridden_repository(repository):
            response = client.get("/api/users", headers=auth_headers)

        assert response.status_code == 200, response.text
        assert response.json()["users"] == []
        assert response.json()["total"] == 0

    @patch.dict("os.environ", {"SHADOW9_API_KEY": "test-api-key"})
    def test_generate_credentials(self, client, auth_headers):
        """Test credential generation."""
        response = client.post("/api/users/generate", headers=auth_headers)
        # Should succeed or fail based on service state
        assert response.status_code in [200, 500]


class TestServerEndpoints:
    """Tests for server management endpoints."""

    @patch.dict("os.environ", {"SHADOW9_API_KEY": "test-api-key"})
    def test_get_server_status(self, client, auth_headers):
        """Test server status endpoint."""
        repository = MagicMock()
        repository.count = AsyncMock(return_value=5)

        with overridden_repository(repository):
            response = client.get("/api/server/status", headers=auth_headers)

        assert response.status_code == 200, response.text
        assert "running" in response.json()

    @patch.dict("os.environ", {"SHADOW9_API_KEY": "test-api-key"})
    @patch("shadow9.api.endpoints.server._something_is_listening", new_callable=AsyncMock)
    def test_status_reports_zero_connections_only_when_nothing_listens(
        self, mock_listening, client, auth_headers
    ):
        """With no listener the counts are genuinely zero, not a guess."""
        mock_listening.return_value = False

        response = client.get("/api/server/status", headers=auth_headers)
        assert response.status_code == 200
        body = response.json()
        assert body["running"] is False
        assert body["active_connections"] == 0
        assert body["uptime_seconds"] is None

    @patch.dict("os.environ", {"SHADOW9_API_KEY": "test-api-key"})
    @patch("shadow9.api.endpoints.server._something_is_listening", new_callable=AsyncMock)
    def test_status_reports_null_connections_when_the_proxy_is_up(
        self, mock_listening, client, auth_headers
    ):
        """The proxy's counters live in another process, so null means unknown."""
        mock_listening.return_value = True

        response = client.get("/api/server/status", headers=auth_headers)
        assert response.status_code == 200
        body = response.json()
        assert body["running"] is True
        assert body["active_connections"] is None
        assert body["uptime_seconds"] is None

    @patch.dict("os.environ", {"SHADOW9_API_KEY": "test-api-key"})
    def test_get_server_config(self, client, auth_headers):
        """Test server config endpoint."""
        settings = Settings()
        settings.wireguard.enabled = True
        settings.wireguard.listen_port = 51987
        settings.wireguard.enrollment_host = "0.0.0.0"
        settings.wireguard.enrollment_port = 8191
        settings.wireguard.tunnel_network = "10.77.0.0/24"
        settings.wireguard.hub_endpoint = "vpn.example.test:51987"
        settings.wireguard.mtu = 1380
        settings.wireguard.dns = ["10.77.0.1", "1.1.1.1"]
        settings.wireguard.keepalive = 19

        def configured_settings() -> Settings:
            return settings

        app.dependency_overrides[get_settings] = configured_settings
        try:
            response = client.get("/api/server/config", headers=auth_headers)
        finally:
            app.dependency_overrides.pop(get_settings, None)

        assert response.status_code == 200
        assert response.json()["wireguard"] == {
            "enabled": True,
            "listen_port": 51987,
            "enrollment_host": "0.0.0.0",
            "enrollment_port": 8191,
            "tunnel_network": "10.77.0.0/24",
            "hub_endpoint": "vpn.example.test:51987",
            "mtu": 1380,
            "dns": ["10.77.0.1", "1.1.1.1"],
            "keepalive": 19,
        }
        assert "private_key" not in response.json()["wireguard"]


class CredentialStore:
    """Stand-in repository that pages exactly the way UserRepository.list does."""

    def __init__(self, credentials: list[Credential]):
        self._credentials = credentials

    async def list(self, skip: int = 0, limit: Optional[int] = 100) -> list[Credential]:
        if limit is None:
            return self._credentials[skip:]
        return self._credentials[skip : skip + limit]

    async def count(self) -> int:
        return len(self._credentials)


def _credential(name: str, enabled: bool) -> Credential:
    """Build a credential with only the fields the listing path reads."""
    return Credential(
        username=name,
        password_hash="argon2-hash",
        enabled=enabled,
        created_at=_utc_now(),
    )


class TestUserListingPagination:
    """Enabled-only listing must filter before the repository slices, not after."""

    @pytest.mark.asyncio
    async def test_enabled_only_fills_the_page(self):
        # 120 disabled accounts ahead of 60 enabled ones, so a page-then-filter
        # implementation returns nothing at all for the first page
        credentials = [_credential(f"off_{i}", enabled=False) for i in range(120)]
        credentials += [_credential(f"on_{i}", enabled=True) for i in range(60)]
        service = UserService(repository=CredentialStore(credentials))

        users = await service.list(skip=0, limit=50, enabled_only=True)

        assert len(users) == 50
        assert all(u.username.startswith("on_") for u in users)

    @pytest.mark.asyncio
    async def test_enabled_only_pages_without_dropping_users(self):
        credentials = [_credential(f"off_{i}", enabled=False) for i in range(120)]
        credentials += [_credential(f"on_{i}", enabled=True) for i in range(60)]
        service = UserService(repository=CredentialStore(credentials))

        first = await service.list(skip=0, limit=50, enabled_only=True)
        second = await service.list(skip=50, limit=50, enabled_only=True)

        seen = [u.username for u in first] + [u.username for u in second]
        assert len(seen) == 60
        assert len(set(seen)) == 60

    @pytest.mark.asyncio
    async def test_a_user_created_mid_listing_is_not_dropped_off_the_page(self):
        """Counting first and then asking for a page of that size reads twice.

        A create landing between the two reads makes the second one longer than the size
        the first reported, and the newest user falls off the end of the slice.
        """
        credentials = [_credential(f"on_{i}", enabled=True) for i in range(12)]

        class StoreThatGrowsBetweenReads(CredentialStore):
            """A create lands just before the page is read, the way another process would.

            reload_if_changed runs at the start of every repository read, so a table that
            was 12 users when count() answered is 13 by the time the page is taken.
            """

            def __init__(self, credentials: list[Credential]):
                super().__init__(credentials)
                self._grown = False

            async def list(self, skip: int = 0, limit: Optional[int] = 100):
                if not self._grown:
                    self._grown = True
                    self._credentials.append(_credential("newest", enabled=True))
                return await super().list(skip=skip, limit=limit)

        service = UserService(repository=StoreThatGrowsBetweenReads(credentials))

        users = await service.list(skip=0, limit=100, enabled_only=True)

        assert [u.username for u in users][-1] == "newest"

    @pytest.mark.asyncio
    async def test_enabled_only_total_excludes_disabled_users(self):
        credentials = [_credential(f"off_{i}", enabled=False) for i in range(120)]
        credentials += [_credential(f"on_{i}", enabled=True) for i in range(60)]
        service = UserService(repository=CredentialStore(credentials))

        assert await service.count(enabled_only=True) == 60
        assert await service.count() == 180


class TestPeerChangesReissueConfigs:
    @pytest.mark.asyncio
    async def test_enable_and_disable_use_the_locked_peer_change(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[tuple[str, bool]] = []
        repository = MagicMock()
        repository.auth_manager = MagicMock()
        repository.update = AsyncMock()

        def change(config: Config, auth_manager: object, name: str, enabled: bool) -> bool:
            calls.append((name, enabled))
            return True

        monkeypatch.setattr(user_service_module, "set_peer_enabled", change)
        service = UserService(repository=repository, config=Config())

        assert await service.disable("phone") is True
        assert await service.enable("phone") is True
        assert calls == [("phone", False), ("phone", True)]
        repository.update.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_delete_uses_the_locked_peer_cleanup(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        removed: list[str] = []
        repository = MagicMock()
        repository.auth_manager = MagicMock()
        repository.delete = AsyncMock()

        def delete(config: Config, auth_manager: object, name: str) -> bool:
            removed.append(name)
            return True

        monkeypatch.setattr(user_service_module, "delete_user_peer", delete)
        service = UserService(repository=repository, config=Config())

        assert await service.delete("phone") is True
        assert removed == ["phone"]
        repository.delete.assert_not_awaited()


class TestPasswordHashingStaysOffTheLoop:
    """argon2 costs 64 MB and hundreds of milliseconds, so it must not run on the loop."""

    @pytest.mark.asyncio
    async def test_create_hashes_in_a_worker_thread(self):
        loop_thread = threading.get_ident()
        hashing_threads = []

        def record_and_hash(password: str) -> str:
            hashing_threads.append(threading.get_ident())
            return "argon2-hash"

        repo = MagicMock()
        repo.exists = AsyncMock(return_value=False)
        repo.hash_password = record_and_hash
        repo.create = AsyncMock(side_effect=lambda credential: credential)

        service = UserService(repository=repo)
        await service.create(UserCreate(username="someone", password="SecurePass123!"))

        assert hashing_threads and loop_thread not in hashing_threads

    @pytest.mark.asyncio
    async def test_update_hashes_in_a_worker_thread(self):
        loop_thread = threading.get_ident()
        hashing_threads = []

        def record_and_hash(password: str) -> str:
            hashing_threads.append(threading.get_ident())
            return "argon2-hash"

        existing = _credential("someone", enabled=True)
        repo = MagicMock()
        repo.exists = AsyncMock(return_value=True)
        repo.hash_password = record_and_hash
        repo.update = AsyncMock(return_value=existing)

        service = UserService(repository=repo)
        await service.update("someone", UserUpdate(password="AnotherPass123!"))

        assert hashing_threads and loop_thread not in hashing_threads

    @pytest.mark.asyncio
    async def test_update_rejects_a_null_on_a_required_field(self):
        """A null use_tor would read as false and route the user's traffic directly."""
        existing = _credential("someone", enabled=True)
        repo = MagicMock()
        repo.exists = AsyncMock(return_value=True)
        repo.update = AsyncMock(return_value=existing)

        service = UserService(repository=repo)

        for field in ("use_tor", "enabled", "bridge_type", "security_level", "logging_enabled"):
            with pytest.raises(ValueError, match=field):
                await service.update("someone", UserUpdate(**{field: None}))

        repo.update.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_update_still_clears_the_three_clearable_fields(self):
        """Absence is a real setting for these three, so an explicit null must reach the store."""
        existing = _credential("someone", enabled=True)
        repo = MagicMock()
        repo.exists = AsyncMock(return_value=True)
        repo.update = AsyncMock(return_value=existing)

        service = UserService(repository=repo)
        await service.update(
            "someone",
            UserUpdate(allowed_ports=None, rate_limit=None, bind_port=None),
        )

        _, written = repo.update.await_args.args
        assert written == {"allowed_ports": None, "rate_limit": None, "bind_port": None}


class TestApiKeyStorage:
    """The admin API key must not be readable in the config file."""

    def _use_temp_files(self, tmp_path):
        """Point the salt file at a temp dir and hand back a temp config path."""
        salt_file = tmp_path / ".api_salt"
        return patch("shadow9.core.api_config._get_api_salt_file", return_value=salt_file)

    @patch("shadow9.core.api_config.load_master_key", return_value="test-master-key")
    def test_stored_key_is_not_readable_in_the_file(self, _mock_master, tmp_path):
        config_file = tmp_path / "api.yaml"

        with self._use_temp_files(tmp_path):
            set_api_key("super-secret-admin-key", config_file)

        written = config_file.read_text(encoding="utf-8")
        assert "super-secret-admin-key" not in written
        assert "api_key_encrypted" in written

    @patch("shadow9.core.api_config.load_master_key", return_value="test-master-key")
    def test_stored_key_round_trips(self, _mock_master, tmp_path):
        config_file = tmp_path / "api.yaml"

        with self._use_temp_files(tmp_path):
            set_api_key("super-secret-admin-key", config_file)
            assert get_api_key(config_file) == "super-secret-admin-key"

    @patch("shadow9.core.api_config.load_master_key", return_value="test-master-key")
    def test_saving_a_key_removes_a_legacy_plaintext_key(self, _mock_master, tmp_path):
        config_file = tmp_path / "api.yaml"
        config_file.write_text(
            "api:\n  key: old-plaintext-key\n  host: 127.0.0.1\n  port: 8080\n", encoding="utf-8"
        )

        with self._use_temp_files(tmp_path):
            set_api_key("replacement-key", config_file)

        written = config_file.read_text(encoding="utf-8")
        assert "old-plaintext-key" not in written
        assert "replacement-key" not in written
        # settings alongside the key survive the move to the flat shape
        assert "8080" in written

    @pytest.mark.skipif(os.name == "nt", reason="POSIX file modes only")
    @patch("shadow9.core.api_config.load_master_key", return_value="test-master-key")
    def test_config_file_is_not_world_readable(self, _mock_master, tmp_path):
        config_file = tmp_path / "api.yaml"

        with self._use_temp_files(tmp_path):
            set_api_key("super-secret-admin-key", config_file)

        assert config_file.stat().st_mode & 0o077 == 0

    def test_a_failed_setup_leaves_the_working_key_in_place(self, tmp_path):
        """Re-running setup without a master key must not take the existing key with it.

        The wizard cannot encrypt the new key, tells the operator to try again, and the
        key that was working has to still be there when they do.
        """
        from shadow9.wizards.api_setup import _save_config

        config_file = tmp_path / "api.yaml"
        with (
            self._use_temp_files(tmp_path),
            patch("shadow9.core.api_config.load_master_key", return_value="test-master-key"),
        ):
            set_api_key("the-original-working-key", config_file)

        with (
            self._use_temp_files(tmp_path),
            patch("shadow9.core.api_config.load_master_key", return_value=None),
        ):
            saved = _save_config(
                {
                    "key": "a-new-key",
                    "host": "0.0.0.0",
                    "port": 9000,
                    "enabled": True,
                    "enable_on_startup": False,
                },
                str(config_file),
            )

        assert saved is False
        with (
            self._use_temp_files(tmp_path),
            patch("shadow9.core.api_config.load_master_key", return_value="test-master-key"),
        ):
            assert get_api_key(config_file) == "the-original-working-key"


class TestServiceOverTheRealStore:
    """The service's own tests run against mocks, so nothing else covers the real store.

    The repository now keeps its records in the same store the proxy uses, which holds
    plain strings, while the API works in pydantic models with datetimes and enums. A
    slip in that conversion would show up as a value that changes shape on its way to the
    file and back, and every other test here would still pass.
    """

    @pytest.mark.asyncio
    async def test_a_user_survives_the_trip_to_the_file_and_back(self, tmp_path):
        creds_file = tmp_path / "credentials.enc"
        repository = UserRepository(credentials_file=creds_file, master_key="a-master-key")
        service = UserService(repository=repository)

        created = await service.create(
            UserCreate(
                username="alice",
                password="SecurePass123!@#",
                bridge_type=BridgeType.OBFS4,
                security_level=SecurityLevel.PARANOID,
                allowed_ports=[443],
                bind_port=1080,
            )
        )
        assert created.bridge_type == BridgeType.OBFS4

        updated = await service.update(
            "alice", UserUpdate(bridge_type=BridgeType.SNOWFLAKE, allowed_ports=None)
        )
        assert updated is not None
        assert updated.bridge_type == BridgeType.SNOWFLAKE
        assert updated.allowed_ports is None

        await repository.update_last_used("alice")

        # a store built from scratch reads only what reached the file
        reader = UserRepository(credentials_file=creds_file, master_key="a-master-key")
        again = await reader.get("alice")

        assert again is not None
        assert again.bridge_type == BridgeType.SNOWFLAKE
        assert again.security_level == SecurityLevel.PARANOID
        assert again.bind_port == 1080
        assert again.allowed_ports is None
        assert isinstance(again.created_at, datetime)
        assert isinstance(again.last_used, datetime)
        assert await reader.count() == 1

        assert await service.delete("alice") is True
        assert await UserRepository(
            credentials_file=creds_file, master_key="a-master-key"
        ).count() == 0


class TestEveryExportedNameExists:
    """A name left in __all__ after its symbol goes breaks `import *` for the whole module.

    Removing a symbol and forgetting its export is silent until somebody does a star
    import, and then it is an AttributeError naming the package rather than the symbol.
    This walks every package that publishes an __all__ and asks for each name.
    """

    @pytest.mark.parametrize(
        "module_name",
        [
            "shadow9",
            "shadow9.api",
            "shadow9.api.endpoints",
            "shadow9.commands",
            "shadow9.core",
            "shadow9.models",
            "shadow9.repositories",
            "shadow9.schemas",
            "shadow9.services",
            "shadow9.wizards",
        ],
    )
    def test_every_name_it_publishes_can_be_reached(self, module_name: str):
        module = importlib.import_module(module_name)
        published = getattr(module, "__all__", [])

        assert published, f"{module_name} publishes nothing, so this list is out of date"
        missing = [name for name in published if not hasattr(module, name)]
        assert missing == []


class TestRootEndpoint:
    """Tests for root endpoint."""

    def test_root(self, client):
        """Test root endpoint."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "name" in data
        assert "version" in data
        assert "docs" in data
