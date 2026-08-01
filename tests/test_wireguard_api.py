"""
Tests for the WireGuard enrollment endpoint.

The request and response shapes here are a contract with a client written in another
language, so the fixtures under `contracts/enrollment/` are loaded rather than restated.
That directory is canonical; the Go module keeps an embedded copy of it because Go's test
cache does not track a file outside the module, and
`tests/test_wireguard_contract.py::TestTheGoModulesCopyIsHonest` holds the two in step.

**The split with `tests/test_wireguard_contract.py`**: that module checks the models, the
manifest and the fixtures against each other with no client involved, so a failure there
says the specification and the models disagree. This module checks what a **running
endpoint** does, so the contract tests here are the ones that need a live answer.

Nothing reaches the network. The TestClient calls the app in-process, and the hub's key,
its token file and its configs all live under `tmp_path`.
"""

import hashlib
import json
import secrets
from collections.abc import Iterator
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from shadow9 import paths
from shadow9.api.app import create_enrollment_app
from shadow9.api.deps import get_auth_manager, get_config
from shadow9.auth import AuthManager
from shadow9.config import Config
from shadow9.services import wireguard_service
from shadow9.services.wireguard_service import (
    NODE_ARCHITECTURES,
    JoinToken,
    StoredConfig,
    create_join_token,
    hub_public_key,
    join_mac_key,
    refresh_key,
    refresh_request_mac,
    refresh_response_mac,
    request_mac,
    save_hub_private_key,
    split_join_token,
    utc_now,
)
from shadow9.wireguard import (
    Peer,
    PeerRole,
    derive_public_key,
    generate_keypair,
    generate_private_key,
    parse_address,
    parse_network,
)

HUB_ENDPOINT = "203.0.113.10:51820"
TUNNEL_NETWORK = "10.9.0.0/24"

CONTRACT = Path(__file__).parent.parent / "contracts" / "enrollment"


def _fixture(name: str) -> dict:
    """Load one of the shared contract fixtures."""
    return json.loads((CONTRACT / name).read_text(encoding="utf-8"))


@pytest.fixture
def hub(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator["_Hub"]:
    """A hub with a key, an endpoint and an empty credential store, all under tmp_path."""
    monkeypatch.setenv("SHADOW9_HOME", str(tmp_path))
    monkeypatch.setattr(paths.Shadow9Paths, "_instance", None)
    monkeypatch.setattr(AuthManager, "ARGON2_TIME_COST", 1)
    monkeypatch.setattr(AuthManager, "ARGON2_MEMORY_COST", 64)
    monkeypatch.setattr(AuthManager, "ARGON2_PARALLELISM", 1)

    (tmp_path / "config").mkdir(parents=True, exist_ok=True)
    private_key = generate_private_key()
    save_hub_private_key(private_key)

    cfg = Config()
    cfg.wireguard.enabled = True
    cfg.wireguard.hub_endpoint = HUB_ENDPOINT
    cfg.wireguard.tunnel_network = TUNNEL_NETWORK

    store = AuthManager(credentials_file=tmp_path / "config" / "credentials.enc")

    app = create_enrollment_app()
    app.dependency_overrides[get_config] = lambda: cfg
    app.dependency_overrides[get_auth_manager] = lambda: store

    yield _Hub(
        root=tmp_path,
        config=cfg,
        store=store,
        private_key=private_key,
        public_key=derive_public_key(private_key),
        client=TestClient(app),
    )

    app.dependency_overrides.clear()
    paths.Shadow9Paths._instance = None


class _Hub:
    """Everything a test needs to talk to one hub."""

    def __init__(
        self,
        root: Path,
        config: Config,
        store: AuthManager,
        private_key: str,
        public_key: str,
        client: TestClient,
    ) -> None:
        self.root = root
        self.config = config
        self.store = store
        self.private_key = private_key
        self.public_key = public_key
        self.client = client

    def token(self, hours: int = 24) -> str:
        """Issue a join token this hub will accept."""
        return create_join_token(self.public_key, hours)

    def request(self, token: str, **overrides: object) -> dict[str, object]:
        """Build and sign the usual enrollment request."""
        try:
            token_id, secret, _ = split_join_token(token)
        except wireguard_service.TokenRejected:
            token_id, secret = token, "invalid-token-secret"
        body: dict[str, object] = {
            "token_id": token_id,
            "name": "office-router",
            "public_key": generate_keypair().public_key,
            "routes": [],
            "nonce": secrets.token_urlsafe(32),
        }
        body.update(overrides)
        routes = body["routes"] if isinstance(body.get("routes"), list) else []
        body["mac"] = request_mac(
            join_mac_key(secret),
            str(body["token_id"]),
            str(body["name"]),
            str(body["public_key"]),
            [str(route) for route in routes],
            str(body["nonce"]),
        )
        return body

    def enroll(self, **overrides: object) -> httpx.Response:
        """POST an enrollment request, with the usual body unless a test changes it."""
        raw_token = overrides.pop("token", self.token())
        assert isinstance(raw_token, str)
        body = self.request(raw_token, **overrides)
        return self.client.post("/api/wireguard/enroll", json=body)

    def refresh(self, name: str, key: str, **overrides: object) -> httpx.Response:
        """POST a signed refresh request for one enrolled node."""
        body: dict[str, object] = {
            "name": name,
            "nonce": secrets.token_urlsafe(32),
        }
        body.update(overrides)
        body["mac"] = refresh_request_mac(key, str(body["name"]), str(body["nonce"]))
        return self.client.post("/api/wireguard/refresh", json=body)

    def hub_config_text(self) -> str:
        """The hub's own rendered config."""
        return (self.root / "config" / "wireguard" / "wg0.conf").read_text(encoding="utf-8")


class TestTheAnswer:
    """Criteria 33 and 34: what comes back, and what never does."""

    def test_the_answer_carries_all_fields(self, hub: "_Hub") -> None:
        response = hub.enroll()

        assert response.status_code == 200, response.text
        assert set(response.json()) == {
            "address",
            "hub_public_key",
            "hub_endpoint",
            "tunnel_network",
            "mtu",
            "keepalive",
            "protocol",
            "mac",
        }

    def test_the_answer_says_which_hub_it_came_from(self, hub: "_Hub") -> None:
        response = hub.enroll()

        assert response.json()["hub_public_key"] == hub.public_key

    def test_the_answer_names_the_endpoint_and_the_tunnel_network(self, hub: "_Hub") -> None:
        answer = hub.enroll().json()

        assert answer["hub_endpoint"] == HUB_ENDPOINT
        assert answer["tunnel_network"] == TUNNEL_NETWORK

    def test_the_answer_carries_the_hubs_tunnel_settings(self, hub: "_Hub") -> None:
        hub.config.wireguard.mtu = 1412
        hub.config.wireguard.keepalive = 20

        answer = hub.enroll().json()

        assert answer["mtu"] == 1412
        assert answer["keepalive"] == 20
        assert answer["protocol"] == wireguard_service.ENROLLMENT_PROTOCOL

    def test_the_first_peer_gets_the_address_after_the_hub(self, hub: "_Hub") -> None:
        assert hub.enroll().json()["address"] == "10.9.0.2"

    def test_the_second_peer_gets_the_next_free_address(self, hub: "_Hub") -> None:
        hub.enroll(name="office-router")
        answer = hub.enroll(name="shed-router").json()

        assert answer["address"] == "10.9.0.3"

    def test_no_private_key_is_ever_returned(self, hub: "_Hub") -> None:
        node = generate_keypair()

        response = hub.enroll(public_key=node.public_key)

        body = response.text
        assert hub.private_key not in body
        assert node.private_key not in body
        assert "private" not in body.lower()
        assert "PrivateKey" not in body

    def test_the_hub_config_gains_the_peer(self, hub: "_Hub") -> None:
        node = generate_keypair()

        hub.enroll(name="office-router", public_key=node.public_key)

        text = hub.hub_config_text()
        assert f"PublicKey = {node.public_key}" in text
        assert "AllowedIPs = 10.9.0.2/32" in text

    def test_a_gateways_routes_reach_the_hub_config(self, hub: "_Hub") -> None:
        node = generate_keypair()

        hub.enroll(public_key=node.public_key, routes=["192.168.1.0/24"])

        assert "AllowedIPs = 10.9.0.2/32, 192.168.1.0/24" in hub.hub_config_text()

    def test_the_peer_is_stored_on_the_user_record(self, hub: "_Hub") -> None:
        node = generate_keypair()

        hub.enroll(name="office-router", public_key=node.public_key, routes=["192.168.1.0/24"])

        credential = hub.store.get_credential("office-router")
        assert credential is not None
        assert credential.wg_public_key == node.public_key
        assert credential.wg_address == "10.9.0.2"
        assert credential.wg_routes == ["192.168.1.0/24"]
        assert credential.wg_role == "node"


class TestRoutePropagation:
    """What a gateway's LAN reaches before nodes pull their current route lists."""

    def test_a_device_already_on_the_tunnel_gains_a_new_gateways_lan(self, hub: "_Hub") -> None:
        device_config = _add_device(hub, "phone")
        assert "192.168.1.0/24" not in device_config.read_text(encoding="utf-8")

        hub.enroll(name="office-router", routes=["192.168.1.0/24"])

        # The hub renders a device's config, so it reissues every one of them when the
        # topology changes. This is the hub plus one gateway plus a phone the plan describes
        assert "192.168.1.0/24" in device_config.read_text(encoding="utf-8")

    def test_the_answer_gives_a_node_the_tunnel_range_and_no_other_lan(self, hub: "_Hub") -> None:
        hub.enroll(name="office-router", routes=["192.168.1.0/24"])

        answer = hub.enroll(name="shed-router", routes=["192.168.2.0/24"]).json()

        # Enrollment keeps its original shape. The complete route list comes from refresh,
        # which is what can update both an earlier node and the node that joined last.
        assert answer["tunnel_network"] == TUNNEL_NETWORK
        assert "192.168.1.0/24" not in json.dumps(answer)


class TestRefresh:
    """An enrolled node pulls complete current routes and endpoint settings."""

    def _enroll(self, hub: "_Hub", name: str, route: str) -> str:
        token = hub.token()
        _, secret, _ = split_join_token(token)
        response = hub.enroll(token=token, name=name, routes=[route])
        assert response.status_code == 200, response.text
        return refresh_key(join_mac_key(secret))

    def test_two_gateways_each_receive_the_other_gateways_lan(self, hub: "_Hub") -> None:
        office_key = self._enroll(hub, "office-router", "192.168.1.0/24")
        shed_key = self._enroll(hub, "shed-router", "192.168.2.0/24")

        office = hub.refresh("office-router", office_key)
        shed = hub.refresh("shed-router", shed_key)

        assert office.status_code == shed.status_code == 200
        assert office.json()["allowed_ips"] == [TUNNEL_NETWORK, "192.168.2.0/24"]
        assert shed.json()["allowed_ips"] == [TUNNEL_NETWORK, "192.168.1.0/24"]
        assert office.json()["revision"] == shed.json()["revision"] == 2

    def test_the_refresh_answer_mac_covers_every_field(self, hub: "_Hub") -> None:
        key = self._enroll(hub, "office-router", "192.168.1.0/24")
        nonce = "fixed-refresh-nonce"
        response = hub.refresh("office-router", key, nonce=nonce)
        assert response.status_code == 200
        answer = response.json()
        assert answer["mac"] == refresh_response_mac(
            key,
            nonce,
            answer["address"],
            answer["hub_public_key"],
            answer["hub_endpoint"],
            answer["tunnel_network"],
            answer["allowed_ips"],
            answer["mtu"],
            answer["keepalive"],
            answer["protocol"],
            answer["revision"],
        )

    def test_an_unknown_name_and_a_bad_mac_get_the_same_refusal(self, hub: "_Hub") -> None:
        key = self._enroll(hub, "office-router", "192.168.1.0/24")
        unknown = hub.refresh("unknown-router", key)
        wrong = hub.refresh("office-router", "00" * 32)

        assert unknown.status_code == wrong.status_code == 401
        assert (
            unknown.json() == wrong.json() == {"detail": "This refresh request is not authorized."}
        )

    def test_the_refresh_key_is_stored_but_never_returned(self, hub: "_Hub") -> None:
        key = self._enroll(hub, "office-router", "192.168.1.0/24")
        credential = hub.store.get_credential("office-router")
        assert credential is not None
        assert credential.wg_refresh_key == key
        assert key not in hub.refresh("office-router", key).text

    def test_revision_changes_once_for_each_topology_change(self, hub: "_Hub") -> None:
        state = hub.root / "config" / "wireguard" / "revision-test.json"
        topology = wireguard_service.load_topology(hub.config, [], hub.public_key)
        assert wireguard_service.topology_revision(topology, state) == 1
        assert wireguard_service.topology_revision(topology, state) == 1

        peer = Peer(
            name="office-router",
            public_key=generate_keypair().public_key,
            address=parse_address("10.9.0.2"),
            role=PeerRole.NODE,
            routes=(parse_network("192.168.1.0/24"),),
        )
        enrolled = topology.with_peer(peer)
        assert wireguard_service.topology_revision(enrolled, state) == 2

        disabled = enrolled.with_peer(replace(peer, enabled=False))
        assert wireguard_service.topology_revision(disabled, state) == 3

        rerouted = disabled.with_peer(
            replace(peer, enabled=False, routes=(parse_network("192.168.2.0/24"),))
        )
        assert wireguard_service.topology_revision(rerouted, state) == 4

        moved = replace(rerouted, hub=replace(rerouted.hub, endpoint="198.51.100.8:51820"))
        assert wireguard_service.topology_revision(moved, state) == 5
        assert wireguard_service.topology_revision(moved.without_peer(peer.name), state) == 6


class TestTokens:
    """Criterion 28: a token is good once, and only until it expires."""

    def test_a_used_token_is_refused_and_names_the_reason(self, hub: "_Hub") -> None:
        token = hub.token()

        first = hub.enroll(token=token, name="office-router")
        second = hub.enroll(token=token, name="shed-router")

        assert first.status_code == 200, first.text
        assert second.status_code == 401
        assert "already used" in second.json()["detail"]

    def test_a_used_token_enrolls_nobody_the_second_time(self, hub: "_Hub") -> None:
        token = hub.token()
        hub.enroll(token=token, name="office-router")
        hub.enroll(token=token, name="shed-router")

        assert hub.store.get_credential("shed-router") is None

    def test_a_retry_with_the_same_name_and_key_returns_the_committed_enrollment(
        self, hub: "_Hub"
    ) -> None:
        token = hub.token()
        keypair = generate_keypair()
        first = hub.enroll(token=token, name="office-router", public_key=keypair.public_key)

        second = hub.enroll(token=token, name="office-router", public_key=keypair.public_key)

        assert first.status_code == 200
        assert second.status_code == 200
        first_answer = first.json()
        second_answer = second.json()
        assert {key: value for key, value in second_answer.items() if key != "mac"} == {
            key: value for key, value in first_answer.items() if key != "mac"
        }

    def test_a_public_key_changed_after_signing_is_refused(self, hub: "_Hub") -> None:
        body = hub.request(hub.token())
        body["public_key"] = generate_keypair().public_key

        response = hub.client.post("/api/wireguard/enroll", json=body)

        assert response.status_code == 401
        assert "invalid MAC" in response.json()["detail"]
        assert hub.store.get_credential("office-router") is None

    def test_the_secret_is_not_in_the_serialized_request(self, hub: "_Hub") -> None:
        token = hub.token()
        _, secret, _ = split_join_token(token)

        serialized = json.dumps(hub.request(token))

        assert secret not in serialized
        assert token not in serialized

    def test_an_expired_token_is_refused_and_names_the_reason(self, hub: "_Hub") -> None:
        token = hub.token()
        _expire_every_token(hub.root)

        response = hub.enroll(token=token, name="office-router")

        assert response.status_code == 401
        assert "expired" in response.json()["detail"]

    def test_a_token_this_hub_never_issued_is_refused(self, hub: "_Hub") -> None:
        response = hub.enroll(token=f"never-issued.a-secret.{hub.public_key}")

        assert response.status_code == 401
        assert "not one this hub issued" in response.json()["detail"]

    def test_a_token_naming_another_hub_is_refused(self, hub: "_Hub") -> None:
        other = generate_keypair()

        response = hub.enroll(token=f"another-id.a-secret.{other.public_key}")

        assert response.status_code == 401
        assert "not one this hub issued" in response.json()["detail"]

    def test_a_token_without_its_two_halves_is_refused(self, hub: "_Hub") -> None:
        response = hub.enroll(token="no-dot-in-here")

        assert response.status_code == 401
        assert "not one this hub issued" in response.json()["detail"]

    def test_a_duplicate_name_does_not_spend_its_token(self, hub: "_Hub") -> None:
        assert hub.enroll(name="office-router").status_code == 200
        token = hub.token()

        response = hub.enroll(name="office-router", token=token)

        assert response.status_code == 409
        token_id = token.partition(".")[0]
        record = next(
            entry for entry in wireguard_service.list_join_tokens() if entry.id == token_id
        )
        assert record.used_at is None

    def test_a_failed_config_write_restores_the_token_peer_and_configs(
        self, hub: "_Hub", monkeypatch: pytest.MonkeyPatch
    ) -> None:
        token = hub.token()

        def fail_write(path: Path, text: str) -> Path:
            raise OSError("disk full")

        monkeypatch.setattr(wireguard_service, "write_config", fail_write)
        response = hub.enroll(name="office-router", token=token)

        assert response.status_code == 503
        assert "were restored" in response.json()["detail"]
        assert hub.store.get_credential("office-router") is None
        assert not (hub.root / "config" / "wireguard" / "wg0.conf").exists()
        token_id = token.partition(".")[0]
        record = next(
            entry for entry in wireguard_service.list_join_tokens() if entry.id == token_id
        )
        assert record.used_at is None


class TestWhatIsRefused:
    """Bad input, named rather than shrugged at."""

    def test_enrollment_needs_no_admin_api_key(
        self, hub: "_Hub", monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("SHADOW9_API_KEY", raising=False)

        assert hub.enroll().status_code == 200

    def test_a_public_key_that_is_not_a_key_is_refused(self, hub: "_Hub") -> None:
        response = hub.enroll(public_key="not-a-key")

        assert response.status_code == 400
        assert "not a WireGuard public key" in response.json()["detail"]

    def test_a_name_with_a_path_in_it_is_refused(self, hub: "_Hub") -> None:
        response = hub.enroll(name="../../etc/wireguard/wg0")

        assert response.status_code == 400
        assert "letters, digits" in response.json()["detail"]

    def test_a_route_with_host_bits_is_refused(self, hub: "_Hub") -> None:
        response = hub.enroll(routes=["192.168.1.1/24"])

        assert response.status_code == 400

    @pytest.mark.parametrize("route", ["0.0.0.0/0", "::/0", "10.9.0.0/24"])
    def test_a_route_that_can_claim_the_tunnel_is_refused(self, hub: "_Hub", route: str) -> None:
        response = hub.enroll(routes=[route])

        assert response.status_code == 400
        assert route in response.json()["detail"]

    def test_a_route_overlapping_another_peers_route_is_refused(self, hub: "_Hub") -> None:
        assert hub.enroll(name="office-router", routes=["192.168.1.0/24"]).status_code == 200

        response = hub.enroll(name="shed-router", routes=["192.168.1.128/25"])

        assert response.status_code == 400
        assert "192.168.1.128/25" in response.json()["detail"]
        assert "office-router" in response.json()["detail"]

    def test_a_name_already_enrolled_is_refused_as_a_conflict(self, hub: "_Hub") -> None:
        hub.enroll(name="office-router")

        response = hub.enroll(name="office-router")

        assert response.status_code == 409
        assert "already a peer" in response.json()["detail"]

    def test_a_body_with_an_unexpected_field_is_refused(self, hub: "_Hub") -> None:
        response = hub.enroll(private_key="please-send-me-one")

        assert response.status_code == 422

    def test_a_hub_that_is_turned_off_says_so(self, hub: "_Hub") -> None:
        hub.config.wireguard.enabled = False

        response = hub.enroll()

        assert response.status_code == 503
        assert "turned off" in response.json()["detail"]

    def test_a_hub_with_no_endpoint_says_so(self, hub: "_Hub") -> None:
        hub.config.wireguard.hub_endpoint = ""

        response = hub.enroll()

        assert response.status_code == 503
        assert "set-endpoint" in response.json()["detail"]

    def test_a_host_with_no_hub_key_says_so(self, hub: "_Hub") -> None:
        (hub.root / "config" / "wireguard" / "hub.key").unlink()

        response = hub.enroll()

        assert response.status_code == 503
        assert "wg init" in response.json()["detail"]


class TestTheSharedContract:
    """Criterion 39's live half: a running endpoint produces what the fixtures describe.

    Only the checks that need a real answer are here. Whether the models, the manifest and
    the fixtures agree with each other is `tests/test_wireguard_contract.py`, which does it
    per field and per type rather than per name, so restating any of it here would be two
    tests asserting one thing and a licence for them to disagree.
    """

    def test_the_response_fixture_has_no_private_key(self) -> None:
        assert "private" not in json.dumps(_fixture("response.json")).lower()

    def test_a_live_answer_has_the_same_fields_as_the_fixture(self, hub: "_Hub") -> None:
        answer = hub.enroll().json()

        assert set(answer) == set(_fixture("response.json"))

    def test_the_fixture_request_is_a_shape_this_endpoint_accepts(self, hub: "_Hub") -> None:
        request = _fixture("request.json")

        response = hub.enroll(
            name=request["name"], public_key=request["public_key"], routes=request["routes"]
        )

        assert response.status_code == 200, response.text

    def test_routes_may_be_left_out_but_not_sent_as_null(self, hub: "_Hub") -> None:
        # The Go client sends [] for a node with no LAN. Leaving the field out is also
        # fine; sending null is not, and finding that out here beats finding it on a router.
        # Omitting it reaching a 200 is also what proves the default is a list: a default of
        # None would enrol nothing and answer 500 when the routes were parsed
        body = hub.request(hub.token(), name="no-lan-node")
        body.pop("routes")
        without = hub.client.post("/api/wireguard/enroll", json=body)
        as_null = hub.enroll(name="null-node", routes=None)

        assert without.status_code == 200, without.text
        assert as_null.status_code == 422

    def test_the_error_fixture_is_the_shape_this_endpoint_raises(self, hub: "_Hub") -> None:
        response = hub.enroll(token="no-dot-in-here")

        assert response.status_code == 401
        assert set(response.json()) == set(_fixture("error.json"))
        assert isinstance(response.json()["detail"], str)


class TestServingTheNodeBinary:
    """Criterion 46: a router fetches the client over HTTP and needs no package feed."""

    @staticmethod
    def _build(hub: "_Hub", *architectures: str) -> dict[str, bytes]:
        """Put fake built binaries where `make -C node dist` would leave them."""
        directory = hub.root / "node" / "dist"
        directory.mkdir(parents=True, exist_ok=True)

        built: dict[str, bytes] = {}
        lines: list[str] = []
        for architecture in architectures:
            body = f"ELF pretend binary for {architecture}".encode()
            (directory / f"shadow9-node-linux-{architecture}").write_bytes(body)
            built[architecture] = body
            lines.append(f"{hashlib.sha256(body).hexdigest()} *shadow9-node-linux-{architecture}")
        (directory / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
        return built

    def test_each_architecture_is_served_byte_for_byte(self, hub: "_Hub") -> None:
        built = self._build(hub, *NODE_ARCHITECTURES)

        for architecture, body in built.items():
            response = hub.client.get(f"/api/wireguard/node/linux-{architecture}")

            assert response.status_code == 200, response.text
            assert response.content == body
            assert response.headers["content-type"] == "application/octet-stream"

    def test_the_download_needs_no_admin_api_key(self, hub: "_Hub", monkeypatch) -> None:
        self._build(hub, "amd64")
        monkeypatch.delenv("SHADOW9_API_KEY", raising=False)

        # A router that has not enrolled holds no credential, and the admin key travels in
        # cleartext over this same connection, so asking for it here would spread the more
        # dangerous secret to fetch the less dangerous file
        assert hub.client.get("/api/wireguard/node/linux-amd64").status_code == 200

    def test_an_architecture_this_project_does_not_build_is_refused(self, hub: "_Hub") -> None:
        self._build(hub, "amd64")

        response = hub.client.get("/api/wireguard/node/linux-s390x")

        assert response.status_code == 404
        assert "amd64" in response.json()["detail"]

    @pytest.mark.parametrize(
        "attempt",
        [
            "linux-..%2f..%2f..%2fconfig%2fwireguard%2fhub.key",
            "linux-../../../config/wireguard/hub.key",
            "linux-..\\..\\config\\wireguard\\hub.key",
            "linux-amd64%00.txt",
        ],
    )
    def test_a_name_that_climbs_out_of_the_build_directory_is_refused(
        self, hub: "_Hub", attempt: str
    ) -> None:
        self._build(hub, "amd64")

        response = hub.client.get(f"/api/wireguard/node/{attempt}")

        # The architecture is matched against an allowlist and the file name is then built
        # from that constant, so nothing off the wire is ever joined onto a path
        assert response.status_code == 404
        assert b"PrivateKey" not in response.content

    def test_a_hub_that_never_built_the_client_says_which_command_to_run(self, hub: "_Hub") -> None:
        response = hub.client.get("/api/wireguard/node/linux-amd64")

        assert response.status_code == 404
        assert "make -C node dist" in response.json()["detail"]

    def test_the_checksums_are_served_and_name_every_build(self, hub: "_Hub") -> None:
        built = self._build(hub, *NODE_ARCHITECTURES)

        response = hub.client.get("/api/wireguard/node/SHA256SUMS")

        assert response.status_code == 200, response.text
        for architecture, body in built.items():
            assert hashlib.sha256(body).hexdigest() in response.text
            assert f"shadow9-node-linux-{architecture}" in response.text

    def test_the_served_checksum_matches_the_served_binary(self, hub: "_Hub") -> None:
        self._build(hub, "amd64")

        binary = hub.client.get("/api/wireguard/node/linux-amd64").content
        recorded = wireguard_service.node_binary_checksums()["amd64"]

        # The operator compares this against sha256sum on the router, which is the only
        # thing making an unauthenticated download over plain HTTP checkable
        assert hashlib.sha256(binary).hexdigest() == recorded

    def test_a_hub_with_no_recorded_checksums_says_which_command_to_run(self, hub: "_Hub") -> None:
        response = hub.client.get("/api/wireguard/node/SHA256SUMS")

        assert response.status_code == 404
        assert "make -C node checksums" in response.json()["detail"]

    @pytest.mark.parametrize(
        "architecture",
        [
            "../../config/wireguard/hub.key",
            "..\\..\\config\\wireguard\\hub.key",
            "/etc/passwd",
            "amd64/../../../hub.key",
            "amd64\x00",
            "AMD64",
            "",
        ],
    )
    def test_the_allowlist_refuses_anything_it_does_not_name(
        self, hub: "_Hub", architecture: str
    ) -> None:
        self._build(hub, "amd64")

        # Asserted here as well as through HTTP, because a 404 from the router would look
        # the same and would not prove this guard does anything
        assert wireguard_service.node_binary_path(architecture) is None

    def test_the_allowlist_serves_the_names_it_does_name(self, hub: "_Hub") -> None:
        self._build(hub, *NODE_ARCHITECTURES)

        for architecture in NODE_ARCHITECTURES:
            path = wireguard_service.node_binary_path(architecture)
            assert path is not None
            assert path.name == f"shadow9-node-linux-{architecture}"

    def test_the_checksum_file_is_read_in_both_sha256sum_formats(self, hub: "_Hub") -> None:
        directory = hub.root / "node" / "dist"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "shadow9-node-linux-amd64").write_bytes(b"one")
        (directory / "shadow9-node-linux-arm64").write_bytes(b"two")
        # sha256sum writes two spaces in text mode and a space then an asterisk in binary
        # mode, and the Makefile produces the second
        (directory / "SHA256SUMS").write_text(
            "aaaa  shadow9-node-linux-amd64\nbbbb *shadow9-node-linux-arm64\n",
            encoding="utf-8",
        )

        assert wireguard_service.node_binary_checksums() == {
            "amd64": "aaaa",
            "arm64": "bbbb",
        }


class TestServingTheNodePackages:
    """OpenWrt packages use the binary route's allowlist and confinement checks."""

    @staticmethod
    def _build_packages(hub: "_Hub", *entries: tuple[str, str]) -> dict[tuple[str, str], bytes]:
        directory = hub.root / "node" / "packages"
        directory.mkdir(parents=True, exist_ok=True)

        built: dict[tuple[str, str], bytes] = {}
        lines: list[str] = []
        for package, architecture in entries:
            name = wireguard_service.NODE_PACKAGE_FILES[package][architecture]
            body = f"pretend {package} package for {architecture}".encode()
            (directory / name).write_bytes(body)
            built[(package, architecture)] = body
            lines.append(f"{hashlib.sha256(body).hexdigest()} *{name}")
        (directory / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
        return built

    def test_each_package_is_served_under_its_release_filename(self, hub: "_Hub") -> None:
        entries = tuple(
            (package, architecture)
            for package in wireguard_service.NODE_PACKAGE_FILES
            for architecture in NODE_ARCHITECTURES
        )
        built = self._build_packages(hub, *entries)

        for (package, architecture), body in built.items():
            response = hub.client.get(f"/api/wireguard/node/package/{package}/{architecture}")

            assert response.status_code == 200, response.text
            assert response.content == body
            assert response.headers["content-disposition"].endswith(
                f'filename="{wireguard_service.NODE_PACKAGE_FILES[package][architecture]}"'
            )

    def test_an_architecture_with_no_package_names_the_release(self, hub: "_Hub") -> None:
        self._build_packages(hub, ("ipk", "amd64"))

        response = hub.client.get("/api/wireguard/node/package/ipk/arm64")

        assert response.status_code == 404
        assert "does not have the ipk node package for 'arm64'" in response.json()["detail"]
        assert wireguard_service.NODE_RELEASE_URL in response.json()["detail"]

    @pytest.mark.parametrize(
        "attempt",
        [
            "..%2f..%2fconfig%2fwireguard%2fhub.key",
            "../../../config/wireguard/hub.key",
            "..\\..\\config\\wireguard\\hub.key",
            "amd64%00.ipk",
        ],
    )
    def test_a_package_name_cannot_climb_out_of_its_directory(
        self, hub: "_Hub", attempt: str
    ) -> None:
        self._build_packages(hub, ("ipk", "amd64"))

        response = hub.client.get(f"/api/wireguard/node/package/ipk/{attempt}")

        assert response.status_code == 404
        assert b"PrivateKey" not in response.content
        assert wireguard_service.node_package_path("ipk", attempt) is None

    def test_package_checksums_are_served(self, hub: "_Hub") -> None:
        built = self._build_packages(hub, ("ipk", "amd64"), ("apk", "arm64"))

        response = hub.client.get("/api/wireguard/node/package/SHA256SUMS")

        assert response.status_code == 200, response.text
        for (package, architecture), body in built.items():
            name = wireguard_service.NODE_PACKAGE_FILES[package][architecture]
            assert hashlib.sha256(body).hexdigest() in response.text
            assert name in response.text
        assert set(wireguard_service.node_package_checksums()) == {
            wireguard_service.NODE_PACKAGE_FILES["ipk"]["amd64"],
            wireguard_service.NODE_PACKAGE_FILES["apk"]["arm64"],
        }


class TestTheRouterIsWired:
    """The endpoint is reachable on the app the entry point builds."""

    def test_the_enroll_route_is_served(self) -> None:
        served = create_enrollment_app().openapi()["paths"]

        assert "/api/wireguard/enroll" in served
        assert set(served["/api/wireguard/enroll"]) == {"post"}
        assert "/api/wireguard/refresh" in served
        assert set(served["/api/wireguard/refresh"]) == {"post"}

    def test_the_default_app_carries_it(self) -> None:
        from shadow9.api.app import enrollment_app as default_app

        assert "/api/wireguard/enroll" in default_app.openapi()["paths"]
        assert "/api/wireguard/refresh" in default_app.openapi()["paths"]

    def test_the_route_does_not_ask_for_an_api_key(self) -> None:
        operation = create_enrollment_app().openapi()["paths"]["/api/wireguard/enroll"]["post"]

        # The join token is the credential here. An admin key would have to be shipped to
        # every router that wants a tunnel, which is a far worse trade
        assert "security" not in operation
        refresh = create_enrollment_app().openapi()["paths"]["/api/wireguard/refresh"]["post"]
        assert "security" not in refresh

    def test_admin_routes_are_not_served(self) -> None:
        client = TestClient(create_enrollment_app())

        assert client.get("/api/users").status_code == 404
        assert client.get("/api/server/config").status_code == 404


def _add_device(hub: "_Hub", name: str) -> Path:
    """Put a device on the hub the way `wg device add` does, and return its config file."""
    from shadow9.wireguard import Peer, PeerRole, config_path, write_config

    keypair = generate_keypair()
    topology = wireguard_service.load_topology(
        hub.config, hub.store.list_credentials(), hub.public_key
    )
    claim = wireguard_service.claim_address(
        topology.tunnel_network, wireguard_service.address_claims(topology), name
    )
    peer = Peer(
        name=name,
        public_key=keypair.public_key,
        address=claim.address,
        role=PeerRole.DEVICE,
    )
    wireguard_service.save_peer(hub.store, peer)

    topology = topology.with_peer(peer)
    path = config_path(name)
    write_config(path, wireguard_service.render_peer_config(topology, peer, keypair.private_key))
    wireguard_service.regenerate_configs(topology, hub.private_key)
    return path


def _expire_every_token(root: Path) -> None:
    """Move every issued token's expiry into the past."""
    from dataclasses import replace

    path = root / "config" / "wireguard" / "join-tokens.json"
    stale = (utc_now() - timedelta(hours=1)).isoformat()
    tokens = [
        replace(token, expires_at=stale) for token in wireguard_service.list_join_tokens(path)
    ]
    assert tokens, "there was nothing to expire"
    wireguard_service._write_tokens(path, tokens)


def test_a_token_record_round_trips_through_the_file(tmp_path: Path) -> None:
    """The stored shape reads back as what was written."""
    token = JoinToken(
        id="token-id",
        mac_key="a" * 64,
        created_at="2026-07-31T09:48:34+00:00",
        expires_at="2026-08-01T09:48:34+00:00",
    )

    assert JoinToken.from_record(token.to_record()) == token


def test_a_token_hash_is_compared_with_compare_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    """The stored id comparison must not stop at the first differing byte."""
    compared: list[tuple[str, str]] = []
    compare_digest = wireguard_service.hmac.compare_digest

    def record_comparison(left: str, right: str) -> bool:
        compared.append((left, right))
        return compare_digest(left, right)

    token = JoinToken(
        id="known-token-id",
        mac_key=join_mac_key("known-secret"),
        created_at=utc_now().isoformat(),
        expires_at=(utc_now() + timedelta(hours=1)).isoformat(),
    )
    monkeypatch.setattr(wireguard_service.hmac, "compare_digest", record_comparison)

    assert wireguard_service._checked_join_token(token.id, [token]) == token
    assert compared == [(token.id, token.id)]


def test_a_stored_config_repr_hides_its_private_key() -> None:
    secret = generate_keypair().private_key
    stored = StoredConfig(
        path=Path("phone.conf"),
        private_key=secret,
        full_tunnel=False,
        obfuscated=False,
    )

    assert secret not in repr(stored)
    assert "<hidden>" in repr(stored)


def test_a_token_file_that_is_not_json_refuses_a_write_and_stays_in_place(tmp_path: Path) -> None:
    """A new token must not replace outstanding tokens the process cannot read."""
    path = tmp_path / "join-tokens.json"
    original = b"this is not json"
    path.write_bytes(original)

    with pytest.raises(OSError, match="not valid JSON"):
        create_join_token(generate_keypair().public_key, path=path)

    assert path.read_bytes() == original


def test_a_token_whose_expiry_cannot_be_read_counts_as_expired() -> None:
    """An unreadable expiry is one nobody can call good."""
    assert wireguard_service._expiry_passed("whenever") is True


def test_the_hub_public_key_comes_from_the_hub_private_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The hub's public key is derived rather than stored a second time."""
    monkeypatch.setenv("SHADOW9_HOME", str(tmp_path))
    monkeypatch.setattr(paths.Shadow9Paths, "_instance", None)
    (tmp_path / "config").mkdir(parents=True, exist_ok=True)

    private_key = generate_private_key()
    save_hub_private_key(private_key)

    assert hub_public_key() == derive_public_key(private_key)
    paths.Shadow9Paths._instance = None
