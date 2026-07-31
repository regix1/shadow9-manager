"""
Tests for the WireGuard CLI commands.

Nothing here reaches the network or the filesystem outside `tmp_path`. `post_enrollment` is
replaced with a function that records what it was asked to send and answers with whatever
the test wants, which is how the hub-key comparison in `wg join` gets tested without a hub.
"""

import json
import re
import sys
import types
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import IO

import pytest
from typer import Typer
from typer.testing import CliRunner

from shadow9 import paths
from shadow9.auth import AuthManager
from shadow9.commands import wireguard as wg_commands
from shadow9.config import Config
from shadow9.services import wireguard_service
from shadow9.wireguard import derive_public_key, generate_keypair

HUB_ENDPOINT = "198.51.100.7:51820"
TUNNEL_NETWORK = "10.9.0.0/24"

# The documentation ranges are what an example uses, but ipaddress calls all of them
# unroutable, so the wizard warns about them and asks a question the scripted answers here
# do not expect. This one is a real globally routable address, which is what the wizard is
# meant to be given.
ROUTABLE_ENDPOINT = "93.184.216.34:51820"


@pytest.fixture
def hub_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Point the whole install at tmp_path, so nothing is written anywhere else."""
    monkeypatch.setenv("SHADOW9_HOME", str(tmp_path))
    # rich wraps to the terminal width, and a wrapped table cell or a wrapped token cannot
    # be searched for as one string. A wide console keeps the assertions about what the
    # operator sees rather than about where rich folded the line
    monkeypatch.setenv("COLUMNS", "200")
    monkeypatch.setattr(paths.Shadow9Paths, "_instance", None)

    # argon2's real parameters cost 64 MB and a few hundred milliseconds per peer, and
    # these tests store a lot of peers. The stored hash is still a real argon2 hash, so the
    # store's own check on it still runs
    monkeypatch.setattr(AuthManager, "ARGON2_TIME_COST", 1)
    monkeypatch.setattr(AuthManager, "ARGON2_MEMORY_COST", 64)
    monkeypatch.setattr(AuthManager, "ARGON2_PARALLELISM", 1)

    (tmp_path / "config").mkdir(parents=True, exist_ok=True)
    yield tmp_path
    paths.Shadow9Paths._instance = None


@pytest.fixture
def runner() -> CliRunner:
    """A Typer runner that keeps stdout and stderr together."""
    return CliRunner()


@pytest.fixture
def cli_app() -> Typer:
    """The real CLI app, built the same way the entry point builds it."""
    from shadow9.cli import app

    return app


def _config_file(root: Path) -> str:
    """The config file path these commands are given."""
    return str(root / "config" / "config.yaml")


def _flat(output: str) -> str:
    """Collapse the wrapping rich does, so a sentence can be searched for as one."""
    return re.sub(r"\s+", " ", output)


def _init_hub(runner: CliRunner, cli_app: Typer, root: Path, *extra: str) -> str:
    """Run `wg init` and return its output."""
    result = runner.invoke(
        cli_app,
        ["wg", "init", "--endpoint", HUB_ENDPOINT, "--config", _config_file(root), *extra],
    )
    assert result.exit_code == 0, result.output
    return result.output


def _wireguard_dir(root: Path) -> Path:
    """Where rendered configs land."""
    return root / "config" / "wireguard"


def _token_from(output: str) -> str:
    """Pull the join token out of a printed join command."""
    flat = _flat(output)
    match = re.search(r"--token (\S+)", flat)
    assert match is not None, flat
    return match.group(1)


class TestInit:
    """`shadow9 wg init` (criterion 25)."""

    def test_init_writes_the_key_the_config_and_prints_a_join_command(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        output = _init_hub(runner, cli_app, hub_root)

        key_file = _wireguard_dir(hub_root) / "hub.key"
        hub_config = _wireguard_dir(hub_root) / "wg0.conf"

        assert key_file.exists()
        assert hub_config.exists()
        assert "ListenPort = 51820" in hub_config.read_text()
        assert "shadow9 wg join" in _flat(output)
        assert "--token" in _flat(output)
        assert "host firewall and the cloud firewall or security group" in _flat(output)
        assert "TCP 8081" in _flat(output)
        assert "UDP 51820" in _flat(output)
        assert "Keep TCP 8080, the admin API port, closed to the internet" in _flat(output)
        assert "requires iptables" in _flat(output)

    def test_the_hub_takes_the_first_address_in_the_tunnel_network(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        _init_hub(runner, cli_app, hub_root)

        text = (_wireguard_dir(hub_root) / "wg0.conf").read_text()
        assert "Address = 10.9.0.1/24" in text

    def test_init_will_not_replace_an_existing_hub_key_without_force(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        _init_hub(runner, cli_app, hub_root)
        first = (_wireguard_dir(hub_root) / "hub.key").read_text()

        result = runner.invoke(
            cli_app, ["wg", "init", "--endpoint", HUB_ENDPOINT, "--config", _config_file(hub_root)]
        )

        assert result.exit_code == 1
        assert "already has a WireGuard hub key" in _flat(result.output)
        assert (_wireguard_dir(hub_root) / "hub.key").read_text() == first

    def test_force_replaces_the_key_and_says_peers_must_rejoin(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        _init_hub(runner, cli_app, hub_root)
        first = (_wireguard_dir(hub_root) / "hub.key").read_text()

        _init_hub(runner, cli_app, hub_root, "--force")

        assert (_wireguard_dir(hub_root) / "hub.key").read_text() != first

    def test_init_says_the_windows_file_mode_does_not_protect_the_key(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        output = _flat(_init_hub(runner, cli_app, hub_root))

        assert "holds a private key" in output

    def test_an_endpoint_that_is_not_routable_is_pointed_out(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        result = runner.invoke(
            cli_app,
            [
                "wg",
                "init",
                "--endpoint",
                "192.168.1.10:51820",
                "--config",
                _config_file(hub_root),
            ],
        )

        assert result.exit_code == 0
        assert "not an address the internet routes to" in _flat(result.output)

    def test_a_bad_tunnel_network_is_refused_by_name(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        result = runner.invoke(
            cli_app,
            [
                "wg",
                "init",
                "--endpoint",
                HUB_ENDPOINT,
                "--network",
                "8.8.8.0/24",
                "--config",
                _config_file(hub_root),
            ],
        )

        assert result.exit_code == 1
        assert "8.8.8.0/24" in _flat(result.output)

    def test_the_masquerade_interface_survives_a_later_reissue(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        _init_hub(runner, cli_app, hub_root, "--masquerade-interface", "eth0")
        assert "MASQUERADE" in (_wireguard_dir(hub_root) / "wg0.conf").read_text()

        result = runner.invoke(
            cli_app,
            ["wg", "hub", "set-endpoint", "203.0.113.9:51820", "--config", _config_file(hub_root)],
        )

        assert result.exit_code == 0, result.output
        rewritten = (_wireguard_dir(hub_root) / "wg0.conf").read_text()
        assert "MASQUERADE" in rewritten
        assert "-o eth0" in rewritten


class TestJoinToken:
    """The token shape and what is kept about it (criteria 26, 28)."""

    def test_the_token_is_a_secret_and_the_hub_public_key(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        output = _init_hub(runner, cli_app, hub_root)
        token = _token_from(output)

        token_id, secret, named_key = token.split(".")
        private_key = (_wireguard_dir(hub_root) / "hub.key").read_text().strip()

        assert token_id
        assert secret
        assert named_key == derive_public_key(private_key)

    def test_only_the_hash_of_the_secret_is_kept(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        output = _init_hub(runner, cli_app, hub_root)
        _, secret, _ = _token_from(output).split(".")

        stored = (_wireguard_dir(hub_root) / "join-tokens.json").read_text()

        assert secret not in stored
        assert "mac_key" in stored
        assert "secret_hash" not in stored

    def test_each_token_command_issues_a_new_one(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        first = _token_from(_init_hub(runner, cli_app, hub_root))

        result = runner.invoke(cli_app, ["wg", "token", "--config", _config_file(hub_root)])
        assert result.exit_code == 0, result.output
        second = _token_from(result.output)

        assert first != second
        stored = json.loads((_wireguard_dir(hub_root) / "join-tokens.json").read_text())
        assert len(stored["tokens"]) == 2

    def test_a_token_command_needs_a_hub(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        result = runner.invoke(cli_app, ["wg", "token", "--config", _config_file(hub_root)])

        assert result.exit_code == 1
        assert "not a WireGuard hub yet" in _flat(result.output)

    def test_the_download_and_its_checksum_are_shown_when_the_client_was_built(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        dist = hub_root / "node" / "dist"
        dist.mkdir(parents=True)
        (dist / "shadow9-node-linux-amd64").write_bytes(b"pretend binary")
        (dist / "SHA256SUMS").write_text("abc123 *shadow9-node-linux-amd64\n", encoding="utf-8")

        flat = _flat(_init_hub(runner, cli_app, hub_root))

        assert "wget -O /usr/sbin/shadow9-node" in flat
        assert "abc123" in flat
        # The whole protection is a human running one command, so the command has to read
        # as a step rather than as a note under three lines of hex
        assert "2. Check what arrived, on the router" in flat
        assert flat.index("sha256sum /usr/sbin/shadow9-node") < flat.index("abc123")
        # The operator has to be told this download is unauthenticated, the same way
        # criterion 36 makes every command say so about the API key, and told what
        # skipping the comparison actually costs
        assert "anyone on the path between the router and this hub" in flat
        assert "trusting every network in between" in flat

    def test_nothing_is_said_about_a_download_that_was_never_built(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        flat = _flat(_init_hub(runner, cli_app, hub_root))

        assert "wget" not in flat


class TestJoin:
    """`shadow9 wg join`, the node side (criterion 27)."""

    @staticmethod
    def _answer(hub_key: str, address: str = "10.9.0.2") -> dict:
        """The fields a hub answers with."""
        return {
            "address": address,
            "hub_public_key": hub_key,
            "hub_endpoint": HUB_ENDPOINT,
            "tunnel_network": TUNNEL_NETWORK,
            "mtu": 1412,
            "keepalive": 20,
            "protocol": wireguard_service.ENROLLMENT_PROTOCOL,
        }

    def _stub_post(self, monkeypatch: pytest.MonkeyPatch, status: int, answer: dict) -> list:
        """Replace the HTTP call and record every request it was handed."""
        sent: list = []

        def _post(url: str, body: dict, timeout: float = 15.0) -> tuple[int, dict]:
            sent.append({"url": url, "body": body})
            returned = dict(answer)
            signed = {
                "address",
                "hub_public_key",
                "hub_endpoint",
                "tunnel_network",
                "mtu",
                "keepalive",
                "protocol",
            }
            if status == 200 and signed.issubset(returned):
                returned["mac"] = wireguard_service.response_mac(
                    wireguard_service.join_mac_key("a-secret"),
                    str(body["nonce"]),
                    str(returned["address"]),
                    str(returned["hub_public_key"]),
                    str(returned["hub_endpoint"]),
                    str(returned["tunnel_network"]),
                    int(returned["mtu"]),
                    int(returned["keepalive"]),
                    int(returned["protocol"]),
                )
            return status, returned

        monkeypatch.setattr(wg_commands, "post_enrollment", _post)
        return sent

    def test_a_node_writes_its_config_when_the_hub_key_matches(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        hub = generate_keypair()
        self._stub_post(monkeypatch, 200, self._answer(hub.public_key))

        result = runner.invoke(
            cli_app,
            [
                "wg",
                "join",
                "--url",
                "http://198.51.100.7:8080",
                "--token",
                f"token-id.a-secret.{hub.public_key}",
                "--name",
                "office-router",
                "--no-apply",
                "--config",
                _config_file(hub_root),
            ],
        )

        assert result.exit_code == 0, result.output
        written = _wireguard_dir(hub_root) / "wg0.conf"
        assert written.exists()
        text = written.read_text()
        assert f"PublicKey = {hub.public_key}" in text
        assert f"Endpoint = {HUB_ENDPOINT}" in text
        assert "Address = 10.9.0.2/32" in text
        assert "MTU = 1412" in text
        assert "PersistentKeepalive = 20" in text

    def test_a_node_refuses_a_hub_whose_key_is_not_the_one_in_its_token(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        expected = generate_keypair()
        impostor = generate_keypair()
        self._stub_post(monkeypatch, 200, self._answer(impostor.public_key))

        result = runner.invoke(
            cli_app,
            [
                "wg",
                "join",
                "--url",
                "http://198.51.100.7:8080",
                "--token",
                f"token-id.a-secret.{expected.public_key}",
                "--name",
                "office-router",
                "--no-apply",
                "--config",
                _config_file(hub_root),
            ],
        )

        assert result.exit_code == 1
        flat = _flat(result.output)
        assert "not the hub the token names" in flat
        assert "private key is saved" in flat
        assert not (_wireguard_dir(hub_root) / "wg0.conf").exists()

    def test_a_node_sends_only_its_public_key(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        hub = generate_keypair()
        sent = self._stub_post(monkeypatch, 200, self._answer(hub.public_key))

        result = runner.invoke(
            cli_app,
            [
                "wg",
                "join",
                "--url",
                "http://198.51.100.7:8080",
                "--token",
                f"token-id.a-secret.{hub.public_key}",
                "--name",
                "office-router",
                "--no-apply",
                "--config",
                _config_file(hub_root),
            ],
        )

        assert result.exit_code == 0, result.output
        body = sent[0]["body"]
        written = (_wireguard_dir(hub_root) / "wg0.conf").read_text()
        private_key = wireguard_service.config_setting(written, "PrivateKey")

        assert private_key is not None
        assert private_key not in json.dumps(body)
        assert derive_public_key(private_key) == body["public_key"]

    def test_a_refused_join_writes_nothing(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        hub = generate_keypair()
        sent = self._stub_post(monkeypatch, 401, {"detail": "This join token was already used."})

        result = runner.invoke(
            cli_app,
            [
                "wg",
                "join",
                "--url",
                "http://198.51.100.7:8080",
                "--token",
                f"token-id.a-secret.{hub.public_key}",
                "--name",
                "office-router",
                "--no-apply",
                "--config",
                _config_file(hub_root),
            ],
        )

        assert result.exit_code == 1
        assert "already used" in _flat(result.output)
        assert not (_wireguard_dir(hub_root) / "wg0.conf").exists()
        staged = _wireguard_dir(hub_root) / "wg0.join.key"
        assert staged.exists()
        assert derive_public_key(staged.read_text().strip()) == sent[0]["body"]["public_key"]

        second = runner.invoke(
            cli_app,
            [
                "wg",
                "join",
                "--url",
                "http://198.51.100.7:8080",
                "--token",
                f"token-id.a-secret.{hub.public_key}",
                "--name",
                "office-router",
                "--no-apply",
                "--config",
                _config_file(hub_root),
            ],
        )
        assert second.exit_code == 1
        assert sent[1]["body"]["public_key"] == sent[0]["body"]["public_key"]

    def test_a_malformed_token_is_refused_before_anything_is_sent(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sent = self._stub_post(monkeypatch, 200, {})

        result = runner.invoke(
            cli_app,
            [
                "wg",
                "join",
                "--url",
                "http://198.51.100.7:8080",
                "--token",
                "no-dot-in-here",
                "--no-apply",
                "--config",
                _config_file(hub_root),
            ],
        )

        assert result.exit_code == 1
        assert sent == []
        assert "does not look like a join token" in _flat(result.output)

    def test_a_gateway_advertises_its_routes(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        hub = generate_keypair()
        sent = self._stub_post(monkeypatch, 200, self._answer(hub.public_key))

        result = runner.invoke(
            cli_app,
            [
                "wg",
                "join",
                "--url",
                "http://198.51.100.7:8080",
                "--token",
                f"token-id.a-secret.{hub.public_key}",
                "--name",
                "office-router",
                "--route",
                "192.168.1.0/24",
                "--no-apply",
                "--config",
                _config_file(hub_root),
            ],
        )

        assert result.exit_code == 0, result.output
        assert sent[0]["body"]["routes"] == ["192.168.1.0/24"]
        assert "ip_forward" in (_wireguard_dir(hub_root) / "wg0.conf").read_text()

    def test_a_route_that_is_not_a_network_is_refused_before_the_token_is_spent(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        hub = generate_keypair()
        sent = self._stub_post(monkeypatch, 200, self._answer(hub.public_key))

        result = runner.invoke(
            cli_app,
            [
                "wg",
                "join",
                "--url",
                "http://198.51.100.7:8080",
                "--token",
                f"token-id.a-secret.{hub.public_key}",
                "--route",
                "192.168.1.1/24",
                "--no-apply",
                "--config",
                _config_file(hub_root),
            ],
        )

        assert result.exit_code == 1
        assert sent == []

    def test_an_answer_missing_a_field_is_refused(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        hub = generate_keypair()
        self._stub_post(monkeypatch, 200, {"address": "10.9.0.2"})

        result = runner.invoke(
            cli_app,
            [
                "wg",
                "join",
                "--url",
                "http://198.51.100.7:8080",
                "--token",
                f"token-id.a-secret.{hub.public_key}",
                "--no-apply",
                "--config",
                _config_file(hub_root),
            ],
        )

        assert result.exit_code == 1
        assert "not a shadow9 hub" in _flat(result.output)
        assert not (_wireguard_dir(hub_root) / "wg0.conf").exists()

    def test_an_unknown_protocol_is_refused_before_writing(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        hub = generate_keypair()
        answer = self._answer(hub.public_key)
        answer["protocol"] = wireguard_service.ENROLLMENT_PROTOCOL + 1
        self._stub_post(monkeypatch, 200, answer)

        result = runner.invoke(
            cli_app,
            [
                "wg",
                "join",
                "--url",
                "http://198.51.100.7:8080",
                "--token",
                f"token-id.a-secret.{hub.public_key}",
                "--no-apply",
                "--config",
                _config_file(hub_root),
            ],
        )

        assert result.exit_code == 1
        assert "enrollment protocol" in _flat(result.output)
        assert not (_wireguard_dir(hub_root) / "wg0.conf").exists()


class TestDeviceAdd:
    """`shadow9 wg device add` (criterion 29)."""

    def test_the_credential_store_is_opened_after_the_topology_lock(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        locked = False

        class StoreOpened(RuntimeError):
            pass

        @contextmanager
        def topology_lock(path: Path) -> Iterator[None]:
            nonlocal locked
            locked = True
            try:
                yield
            finally:
                locked = False

        def load_config(path: str) -> Config:
            return Config()

        def hub_key() -> str:
            return generate_keypair().private_key

        def open_store(cfg: Config) -> AuthManager:
            assert locked is True
            raise StoreOpened

        monkeypatch.setattr(wg_commands, "lock_file", topology_lock)
        monkeypatch.setattr(wg_commands, "_load_config", load_config)
        monkeypatch.setattr(wg_commands, "_require_hub_private_key", hub_key)
        monkeypatch.setattr(wg_commands, "_auth_manager", open_store)

        with pytest.raises(StoreOpened):
            wg_commands._device_add_impl("phone", False, False, "config.yaml")

    def test_a_device_gets_a_config_and_the_output_says_the_hub_made_the_key(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        _init_hub(runner, cli_app, hub_root)

        result = runner.invoke(
            cli_app, ["wg", "device", "add", "phone", "--config", _config_file(hub_root)]
        )

        assert result.exit_code == 0, result.output
        config = _wireguard_dir(hub_root) / "phone.conf"
        assert config.exists()
        assert "PrivateKey" in config.read_text()
        assert "hub generated this device's private key" in _flat(result.output)
        assert "phone must scan the new QR before a later topology change takes effect" in _flat(
            result.output
        )
        assert "Delete the file" not in result.output

        store = AuthManager(credentials_file=hub_root / "config" / "credentials.enc")
        credential = store.get_credential("phone")
        assert credential is not None
        assert credential.wg_private_key == wireguard_service.config_setting(
            config.read_text(), "PrivateKey"
        )

    def test_a_deleted_device_config_is_rebuilt_from_the_credential_store(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        _init_hub(runner, cli_app, hub_root)
        runner.invoke(cli_app, ["wg", "device", "add", "phone", "--config", _config_file(hub_root)])
        config = _wireguard_dir(hub_root) / "phone.conf"
        private_key = wireguard_service.config_setting(config.read_text(), "PrivateKey")
        config.unlink()

        result = runner.invoke(
            cli_app,
            ["wg", "hub", "set-endpoint", HUB_ENDPOINT, "--config", _config_file(hub_root)],
        )

        assert result.exit_code == 0, result.output
        assert config.exists()
        assert wireguard_service.config_setting(config.read_text(), "PrivateKey") == private_key

    def test_split_tunnel_is_the_default(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        _init_hub(runner, cli_app, hub_root)
        runner.invoke(cli_app, ["wg", "device", "add", "phone", "--config", _config_file(hub_root)])

        text = (_wireguard_dir(hub_root) / "phone.conf").read_text()

        assert "AllowedIPs = 10.9.0.0/24" in text
        assert "0.0.0.0/0" not in text

    def test_full_tunnel_sends_everything_and_resolves_through_the_hub(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        _init_hub(runner, cli_app, hub_root)
        result = runner.invoke(
            cli_app,
            [
                "wg",
                "device",
                "add",
                "laptop",
                "--full-tunnel",
                "--config",
                _config_file(hub_root),
            ],
        )

        assert result.exit_code == 0, result.output
        text = (_wireguard_dir(hub_root) / "laptop.conf").read_text()
        assert "AllowedIPs = 0.0.0.0/0, ::/0" in text
        assert "DNS = 10.9.0.1" in text

    def test_a_full_tunnel_device_says_the_hub_will_not_nat_it_out(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        _init_hub(runner, cli_app, hub_root)
        result = runner.invoke(
            cli_app,
            ["wg", "device", "add", "laptop", "--full-tunnel", "--config", _config_file(hub_root)],
        )

        assert "not set to NAT that traffic out" in _flat(result.output)

    def test_obfuscate_writes_only_the_client_side_parameters(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        _init_hub(runner, cli_app, hub_root)
        result = runner.invoke(
            cli_app,
            ["wg", "device", "add", "phone", "--obfuscate", "--config", _config_file(hub_root)],
        )

        assert result.exit_code == 0, result.output
        text = (_wireguard_dir(hub_root) / "phone.conf").read_text()
        assert "Jc = 6" in text
        assert "Jmax = 1200" in text
        for both_ends in ("H1 =", "H2 =", "S1 =", "S2 ="):
            assert both_ends not in text

    def test_the_second_device_gets_the_next_free_address(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        _init_hub(runner, cli_app, hub_root)
        runner.invoke(cli_app, ["wg", "device", "add", "phone", "--config", _config_file(hub_root)])
        runner.invoke(
            cli_app, ["wg", "device", "add", "tablet", "--config", _config_file(hub_root)]
        )

        assert "Address = 10.9.0.2/32" in (_wireguard_dir(hub_root) / "phone.conf").read_text()
        assert "Address = 10.9.0.3/32" in (_wireguard_dir(hub_root) / "tablet.conf").read_text()

    def test_a_name_that_is_already_a_peer_is_refused(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        _init_hub(runner, cli_app, hub_root)
        runner.invoke(cli_app, ["wg", "device", "add", "phone", "--config", _config_file(hub_root)])

        result = runner.invoke(
            cli_app, ["wg", "device", "add", "phone", "--config", _config_file(hub_root)]
        )

        assert result.exit_code == 1
        assert "already a peer" in _flat(result.output)

    def test_a_device_needs_an_endpoint_to_dial(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        result = runner.invoke(cli_app, ["wg", "init", "--config", _config_file(hub_root)])
        assert result.exit_code == 0, result.output

        result = runner.invoke(
            cli_app, ["wg", "device", "add", "phone", "--config", _config_file(hub_root)]
        )

        assert result.exit_code == 1
        assert "set-endpoint" in _flat(result.output)

    def test_without_the_qr_extra_the_config_is_still_written(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setitem(sys.modules, "qrcode", None)
        _init_hub(runner, cli_app, hub_root)

        result = runner.invoke(
            cli_app, ["wg", "device", "add", "phone", "--config", _config_file(hub_root)]
        )

        assert result.exit_code == 0, result.output
        assert (_wireguard_dir(hub_root) / "phone.conf").exists()
        assert "'qr' extra is not installed" in _flat(result.output)
        assert not (_wireguard_dir(hub_root) / "phone.svg").exists()

    def test_with_the_qr_extra_a_qr_file_is_written(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_fake_qrcode(monkeypatch)
        _init_hub(runner, cli_app, hub_root)

        result = runner.invoke(
            cli_app, ["wg", "device", "add", "phone", "--config", _config_file(hub_root)]
        )

        assert result.exit_code == 0, result.output
        qr_file = _wireguard_dir(hub_root) / "phone.svg"
        assert qr_file.exists()
        assert "PrivateKey" in qr_file.read_text()


class TestList:
    """`shadow9 wg list` (criterion 30)."""

    def test_the_table_names_the_role_the_address_and_the_routes(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _init_hub(runner, cli_app, hub_root)
        runner.invoke(cli_app, ["wg", "device", "add", "phone", "--config", _config_file(hub_root)])
        _store_node_peer(hub_root, "office-router", "10.9.0.9", ["192.168.1.0/24"])

        result = runner.invoke(cli_app, ["wg", "list", "--config", _config_file(hub_root)])

        assert result.exit_code == 0, result.output
        flat = _flat(result.output)
        assert "10.9.0.1" in flat
        assert "phone" in flat
        assert "device" in flat
        assert "192.168.1.0/24" in flat

    def test_a_handshake_nobody_can_read_is_shown_as_unknown(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        _init_hub(runner, cli_app, hub_root)

        result = runner.invoke(cli_app, ["wg", "list", "--config", _config_file(hub_root)])

        assert "unknown" in result.output


class TestRemove:
    """`shadow9 wg remove` (criterion 31)."""

    def test_removing_a_peer_takes_it_out_of_the_hub_config(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        _init_hub(runner, cli_app, hub_root)
        runner.invoke(cli_app, ["wg", "device", "add", "phone", "--config", _config_file(hub_root)])
        assert "# phone" in (_wireguard_dir(hub_root) / "wg0.conf").read_text()

        result = runner.invoke(
            cli_app, ["wg", "remove", "phone", "--yes", "--config", _config_file(hub_root)]
        )

        assert result.exit_code == 0, result.output
        assert "# phone" not in (_wireguard_dir(hub_root) / "wg0.conf").read_text()
        assert not (_wireguard_dir(hub_root) / "phone.conf").exists()

    def test_removing_a_gateway_takes_its_lan_out_of_every_other_config(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        _init_hub(runner, cli_app, hub_root)
        runner.invoke(cli_app, ["wg", "device", "add", "phone", "--config", _config_file(hub_root)])
        _store_node_peer(hub_root, "office-router", "10.9.0.9", ["192.168.1.0/24"])

        runner.invoke(
            cli_app,
            ["wg", "hub", "set-endpoint", HUB_ENDPOINT, "--config", _config_file(hub_root)],
        )
        assert "192.168.1.0/24" in (_wireguard_dir(hub_root) / "phone.conf").read_text()

        result = runner.invoke(
            cli_app, ["wg", "remove", "office-router", "--yes", "--config", _config_file(hub_root)]
        )

        assert result.exit_code == 0, result.output
        assert "192.168.1.0/24" not in (_wireguard_dir(hub_root) / "phone.conf").read_text()

    def test_the_user_record_is_kept(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        _init_hub(runner, cli_app, hub_root)
        runner.invoke(cli_app, ["wg", "device", "add", "phone", "--config", _config_file(hub_root)])

        runner.invoke(
            cli_app, ["wg", "remove", "phone", "--yes", "--config", _config_file(hub_root)]
        )

        store = AuthManager(credentials_file=hub_root / "config" / "credentials.enc")
        credential = store.get_credential("phone")
        assert credential is not None
        assert credential.wg_public_key is None

    def test_removing_something_that_is_not_a_peer_says_so(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        _init_hub(runner, cli_app, hub_root)

        result = runner.invoke(
            cli_app, ["wg", "remove", "nobody", "--yes", "--config", _config_file(hub_root)]
        )

        assert result.exit_code == 1
        assert "not a peer" in _flat(result.output)


class TestSetEndpoint:
    """`shadow9 wg hub set-endpoint` (criterion 32)."""

    def test_the_endpoint_is_rewritten_in_every_config_the_hub_holds(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        _init_hub(runner, cli_app, hub_root)
        runner.invoke(cli_app, ["wg", "device", "add", "phone", "--config", _config_file(hub_root)])

        result = runner.invoke(
            cli_app,
            ["wg", "hub", "set-endpoint", "203.0.113.9:51821", "--config", _config_file(hub_root)],
        )

        assert result.exit_code == 0, result.output
        assert (
            "Endpoint = 203.0.113.9:51821" in (_wireguard_dir(hub_root) / "phone.conf").read_text()
        )

    def test_the_new_endpoint_is_saved_to_the_config_file(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        _init_hub(runner, cli_app, hub_root)

        runner.invoke(
            cli_app,
            ["wg", "hub", "set-endpoint", "203.0.113.9:51821", "--config", _config_file(hub_root)],
        )

        assert "203.0.113.9:51821" in Path(_config_file(hub_root)).read_text()

    def test_peers_the_hub_cannot_reach_are_named(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        _init_hub(runner, cli_app, hub_root)
        _store_node_peer(hub_root, "office-router", "10.9.0.9", ["192.168.1.0/24"])

        result = runner.invoke(
            cli_app,
            ["wg", "hub", "set-endpoint", "203.0.113.9:51821", "--config", _config_file(hub_root)],
        )

        assert result.exit_code == 0, result.output
        flat = _flat(result.output)
        assert "office-router" in flat
        assert "hold their own config" in flat
        assert "next refresh or boot" in flat
        assert "shadow9-node refresh" in flat

    def test_an_endpoint_without_a_port_gets_the_default_one(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        _init_hub(runner, cli_app, hub_root)

        result = runner.invoke(
            cli_app,
            ["wg", "hub", "set-endpoint", "203.0.113.9", "--config", _config_file(hub_root)],
        )

        assert result.exit_code == 0, result.output
        assert "203.0.113.9:51820" in _flat(result.output)

    def test_an_endpoint_with_a_bad_port_is_refused(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        _init_hub(runner, cli_app, hub_root)

        result = runner.invoke(
            cli_app,
            ["wg", "hub", "set-endpoint", "203.0.113.9:99999", "--config", _config_file(hub_root)],
        )

        assert result.exit_code == 1
        assert "not a port" in _flat(result.output)


class TestTheCleartextNotice:
    """Every command names the enrollment secret that actually crosses plain HTTP."""

    @pytest.mark.parametrize(
        "command",
        [
            ["wg", "init", "--endpoint", HUB_ENDPOINT],
            ["wg", "token"],
            ["wg", "list"],
            ["wg", "device", "add", "phone"],
            ["wg", "remove", "phone", "--yes"],
            ["wg", "hub", "set-endpoint", "203.0.113.9:51820"],
        ],
    )
    def test_the_notice_is_printed(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path, command: list[str]
    ) -> None:
        if command[1] != "init":
            _init_hub(runner, cli_app, hub_root)
        if command[:3] == ["wg", "remove", "phone"]:
            runner.invoke(
                cli_app, ["wg", "device", "add", "phone", "--config", _config_file(hub_root)]
            )

        result = runner.invoke(cli_app, [*command, "--config", _config_file(hub_root)])

        assert result.exit_code == 0, result.output
        flat = _flat(result.output)
        assert "Enrollment uses plain HTTP" in flat
        assert "The token secret is not sent" in flat
        assert "anyone on the path can still stop a join" in flat
        assert "denial of service is accepted" in flat
        assert "admin API key travels" not in flat


class TestTheWizard:
    """Criterion 35: hub setup without reading any flags."""

    def test_the_wizard_sets_the_hub_up_from_answers(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        answers = "\n".join([ROUTABLE_ENDPOINT, "10.9.0.0/24", "51820", "n", "y"]) + "\n"

        result = runner.invoke(
            cli_app, ["wg", "setup", "--config", _config_file(hub_root)], input=answers
        )

        assert result.exit_code == 0, result.output
        assert (_wireguard_dir(hub_root) / "hub.key").exists()
        assert (_wireguard_dir(hub_root) / "wg0.conf").exists()
        assert ROUTABLE_ENDPOINT in Path(_config_file(hub_root)).read_text()

    def test_the_wizard_refuses_an_endpoint_it_cannot_use(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        answers = (
            "\n".join(["not an endpoint:abc", ROUTABLE_ENDPOINT, "10.9.0.0/24", "51820", "n", "y"])
            + "\n"
        )

        result = runner.invoke(
            cli_app, ["wg", "setup", "--config", _config_file(hub_root)], input=answers
        )

        assert result.exit_code == 0, result.output
        assert "does not end in a port number" in _flat(result.output)
        assert (_wireguard_dir(hub_root) / "hub.key").exists()

    def test_the_wizard_asks_before_using_an_address_the_internet_cannot_route(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        answers = "\n".join(["192.168.1.10:51820", "y", "10.9.0.0/24", "51820", "n", "y"]) + "\n"

        result = runner.invoke(
            cli_app, ["wg", "setup", "--config", _config_file(hub_root)], input=answers
        )

        assert result.exit_code == 0, result.output
        assert "not an address the internet routes to" in _flat(result.output)
        assert (_wireguard_dir(hub_root) / "hub.key").exists()

    def test_backing_out_writes_nothing(
        self, runner: CliRunner, cli_app: Typer, hub_root: Path
    ) -> None:
        answers = "\n".join([ROUTABLE_ENDPOINT, "10.9.0.0/24", "51820", "n", "n"]) + "\n"

        result = runner.invoke(
            cli_app, ["wg", "setup", "--config", _config_file(hub_root)], input=answers
        )

        assert result.exit_code == 0, result.output
        assert not (_wireguard_dir(hub_root) / "hub.key").exists()


class TestRegistration:
    """The group is wired into the CLI once."""

    def test_wg_is_registered_exactly_once(self, runner: CliRunner, cli_app: Typer) -> None:
        result = runner.invoke(cli_app, ["--help"])

        assert result.exit_code == 0
        assert _flat(result.output).count(" wg ") >= 1

    def test_every_wg_command_is_reachable(self, runner: CliRunner, cli_app: Typer) -> None:
        for command in (
            ["wg", "--help"],
            ["wg", "init", "--help"],
            ["wg", "join", "--help"],
            ["wg", "device", "add", "--help"],
            ["wg", "list", "--help"],
            ["wg", "remove", "--help"],
            ["wg", "hub", "set-endpoint", "--help"],
            ["wg", "token", "--help"],
            ["wg", "setup", "--help"],
        ):
            result = runner.invoke(cli_app, command)
            assert result.exit_code == 0, f"{command}: {result.output}"


def _store_node_peer(root: Path, name: str, address: str, routes: list[str]) -> None:
    """Put a node peer in the store directly, the way an enrollment would."""
    from shadow9.wireguard import Peer, PeerRole, parse_address, parse_network

    store = AuthManager(credentials_file=root / "config" / "credentials.enc")
    wireguard_service.save_peer(
        store,
        Peer(
            name=name,
            public_key=generate_keypair().public_key,
            address=parse_address(address),
            role=PeerRole.NODE,
            routes=tuple(parse_network(route) for route in routes),
        ),
    )


def _install_fake_qrcode(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stand in for the optional qrcode package, which is not a test dependency."""

    class _Image:
        def __init__(self, payload: str) -> None:
            self._payload = payload

        def save(self, stream: IO[bytes]) -> None:
            stream.write(f"<svg>{self._payload}</svg>".encode())

    class _QRCode:
        def __init__(self, border: int = 1) -> None:
            self._payload = ""

        def add_data(self, data: str) -> None:
            self._payload = data

        def make(self, fit: bool = True) -> None:
            return None

        def print_ascii(self, out: IO[str]) -> None:
            out.write("##  ##\n")

        def make_image(self, image_factory: object = None) -> "_Image":
            return _Image(self._payload)

    module = types.ModuleType("qrcode")
    module.QRCode = _QRCode
    svg = types.ModuleType("qrcode.image.svg")
    svg.SvgPathImage = object
    image = types.ModuleType("qrcode.image")
    image.svg = svg
    module.image = image

    monkeypatch.setitem(sys.modules, "qrcode", module)
    monkeypatch.setitem(sys.modules, "qrcode.image", image)
    monkeypatch.setitem(sys.modules, "qrcode.image.svg", svg)
