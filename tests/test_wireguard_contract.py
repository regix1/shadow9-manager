"""
The Python half of the enrollment contract.

The hub answers in Python and the node client parses in Go, and nothing catches a
mismatch between them at compile time. The classic failure is the hub gaining a field,
the node silently ignoring it, and a tunnel that comes up subtly wrong months later.

So the contract is a specified artifact. `contracts/enrollment/fields.json` names every
field, its type and whether it is required, and `request.json` and `response.json` are
worked examples. This module checks the pydantic models against those files. The Go suite
checks its own structs against the same files in `node/internal/enroll/contract_test.go`.
A field added on one side alone fails a test on both.

The split with `tests/test_wireguard_api.py` is deliberate and neither side restates the
other. `TestTheSharedContract` there holds the checks that need a running endpoint: a live
answer against `response.json`, the request fixture against a real 200, `routes` omitted
versus null over HTTP, and the error shape from a real refusal. **This module holds the
checks that need no client**: the manifest against the models per field, per type and per
required-ness, the fixtures against the models, and whether the two fixtures are a matched
pair. A failure here says the specification and the models disagree; a failure there says
a request went wrong.

The last class is the one that is easy to skip and should not be: the Go module carries a
byte-identical copy of these files, because **Go's test cache does not track a file
outside the module**. A Go test that read them by path went on reporting a stale pass
after the contract changed, which is the exact way this check decays without anyone
noticing. Embedding the copy makes each file a build input. Keeping the copy honest is
this module's job, because pytest has no cache to go stale on.

"It worked against a live hub" is not evidence here: a hub and a node that drifted
together still agree with each other.
"""

from __future__ import annotations

import json
import typing
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError
from pydantic.fields import FieldInfo

from shadow9.api.endpoints.wireguard import router
from shadow9.schemas.wireguard import (
    EnrollmentRequest,
    EnrollmentResponse,
    RefreshRequest,
    RefreshResponse,
)
from shadow9.services.wireguard_service import (
    join_mac_key,
    refresh_key,
    refresh_request_mac,
    refresh_response_mac,
    request_mac,
    response_mac,
)

REPO_ROOT: Path = Path(__file__).resolve().parents[1]

# The one place the shapes are written down.
CONTRACT_DIR: Path = REPO_ROOT / "contracts" / "enrollment"

# The copy embedded into the Go module, kept byte for byte identical by
# TestTheGoModulesCopyIsHonest below.
MIRROR_DIR: Path = REPO_ROOT / "node" / "internal" / "contract"

# Every file the Go side embeds. error.json is there so a Go test can check that the
# shape it parses a refusal out of is the shape the hub really sends.
MIRRORED_FILES: tuple[str, ...] = (
    "fields.json",
    "request.json",
    "response.json",
    "refresh-request.json",
    "refresh-response.json",
    "error.json",
)

# The prefix the app mounts the WireGuard router under, from api/app.py.
API_PREFIX: str = "/api"


def read_contract() -> dict[str, Any]:
    """Load the field manifest both test suites read."""
    return json.loads((CONTRACT_DIR / "fields.json").read_text(encoding="utf-8"))


def read_fixture(name: str) -> dict[str, Any]:
    """Load one worked example."""
    return json.loads((CONTRACT_DIR / name).read_text(encoding="utf-8"))


def contract_type_of(annotation: Any) -> str:
    """Name a Python annotation the way the manifest names it."""
    if annotation is str:
        return "string"
    if annotation is bool:
        return "boolean"
    if annotation is int:
        return "integer"
    if typing.get_origin(annotation) is list and typing.get_args(annotation) == (str,):
        return "string[]"
    raise AssertionError(f"the contract has no name for the Python type {annotation!r}")


def described_fields(model: type[BaseModel]) -> list[dict[str, Any]]:
    """Describe a model the way the manifest describes it, in declaration order."""
    described: list[dict[str, Any]] = []
    for name, field in model.model_fields.items():
        assert isinstance(field, FieldInfo)
        described.append(
            {
                "name": name,
                "type": contract_type_of(field.annotation),
                "required": field.is_required(),
            }
        )
    return described


def assert_side_matches(side: str, model: type[BaseModel]) -> None:
    """Compare one side of the contract with its pydantic model, field for field."""
    expected: list[dict[str, Any]] = read_contract()[side]["fields"]
    actual = described_fields(model)

    expected_names = [field["name"] for field in expected]
    actual_names = [field["name"] for field in actual]
    assert actual_names == expected_names, (
        f"{model.__name__} has fields {actual_names} and "
        f"contracts/enrollment/fields.json has {expected_names}. "
        "A field added on one side without the other is what this test is for: "
        "update the manifest, the Go struct in node/internal/enroll and the fixtures together."
    )
    assert (
        actual == expected
    ), f"{model.__name__} does not match the manifest.\nmodel:    {actual}\nmanifest: {expected}"


class TestTheModelsMatchTheManifest:
    """The manifest is the specification and the models have to agree with it."""

    def test_the_request_model_matches(self) -> None:
        assert_side_matches("request", EnrollmentRequest)

    def test_the_response_model_matches(self) -> None:
        assert_side_matches("response", EnrollmentResponse)

    def test_the_refresh_request_model_matches(self) -> None:
        assert_side_matches("refresh_request", RefreshRequest)

    def test_the_refresh_response_model_matches(self) -> None:
        assert_side_matches("refresh_response", RefreshResponse)

    def test_the_manifest_names_the_models_it_describes(self) -> None:
        contract = read_contract()
        assert contract["request"]["python_model"].endswith(".EnrollmentRequest")
        assert contract["response"]["python_model"].endswith(".EnrollmentResponse")
        assert contract["refresh_request"]["python_model"].endswith(".RefreshRequest")
        assert contract["refresh_response"]["python_model"].endswith(".RefreshResponse")

    def test_the_manifest_names_the_real_endpoint(self) -> None:
        contract = read_contract()["endpoint"]
        # A route's path already carries its router's prefix; only the mount point
        # the app adds is missing.
        paths = {API_PREFIX + route.path for route in router.routes}
        assert (
            contract["path"] in paths
        ), f"the manifest says the node posts to {contract['path']} and this app serves {paths}"
        assert contract["method"] == "POST"
        assert contract["success_status"] == 200

        refresh_contract = read_contract()["refresh_endpoint"]
        assert refresh_contract["path"] in paths
        assert refresh_contract["method"] == "POST"
        assert refresh_contract["success_status"] == 200


class TestTheFixturesAreWhatTheModelsAccept:
    """The worked examples have to parse, or the Go side is testing against fiction."""

    def test_the_request_fixture_validates(self) -> None:
        request = EnrollmentRequest.model_validate(read_fixture("request.json"))
        assert request.token_id
        assert request.name
        assert request.public_key
        assert request.routes == ["192.168.1.0/24"]
        assert request.nonce
        assert request.mac

    def test_the_response_fixture_validates(self) -> None:
        response = EnrollmentResponse.model_validate(read_fixture("response.json"))
        assert response.address == "10.9.0.7"
        assert response.hub_endpoint == "203.0.113.10:51820"
        assert response.tunnel_network == "10.9.0.0/24"
        assert response.mtu == 1412
        assert response.keepalive == 20
        assert response.protocol == 1

    def test_the_refresh_fixtures_validate(self) -> None:
        request = RefreshRequest.model_validate(read_fixture("refresh-request.json"))
        response = RefreshResponse.model_validate(read_fixture("refresh-response.json"))
        assert request.name == "branch-gateway"
        assert response.allowed_ips == ["10.9.0.0/24", "192.168.2.0/24"]
        assert response.revision == 7

    def test_the_response_fixture_is_exactly_what_the_model_produces(self) -> None:
        """
        Dumping the model has to give back the fixture, key for key.

        Validating only proves the fixture is acceptable. This proves the hub emits
        nothing more and nothing less, which is the direction a silently added field
        would slip through.
        """
        fixture = read_fixture("response.json")
        produced = EnrollmentResponse.model_validate(fixture).model_dump()
        assert produced == fixture

    def test_both_sides_reject_a_field_neither_knows(self) -> None:
        """
        The Python models set extra="forbid". The Go client deliberately ignores response
        fields it does not need, but the hub must not accept an unknown request field.
        """
        with pytest.raises(ValidationError):
            EnrollmentRequest.model_validate({**read_fixture("request.json"), "mtu": 1420})
        with pytest.raises(ValidationError):
            EnrollmentResponse.model_validate(
                {**read_fixture("response.json"), "allowed_ips": ["10.9.0.0/24"]}
            )

    # Whether `routes` may be omitted and may not be null is pinned against a running
    # endpoint by TestTheSharedContract::test_routes_may_be_left_out_but_not_sent_as_null
    # in tests/test_wireguard_api.py. Asserting it again here against the model alone
    # would be two tests for one rule and a licence for them to disagree.


class TestTheFixturePairHangsTogether:
    """
    The two languages must produce the same signatures for the worked exchange. Both
    fixture MACs are checked from the example secret rather than assumed.
    """

    def test_the_token_in_the_request_names_the_hub_in_the_response(self) -> None:
        request = read_fixture("request.json")
        response = read_fixture("response.json")
        mac_key = join_mac_key(read_contract()["example_secret"])

        assert request["mac"] == request_mac(
            mac_key,
            request["token_id"],
            request["name"],
            request["public_key"],
            request["routes"],
            request["nonce"],
        )
        assert response["mac"] == response_mac(
            mac_key,
            request["nonce"],
            response["address"],
            response["hub_public_key"],
            response["hub_endpoint"],
            response["tunnel_network"],
            response["mtu"],
            response["keepalive"],
            response["protocol"],
        )

    def test_the_keys_in_the_fixtures_are_real_wireguard_keys(self) -> None:
        from shadow9.wireguard.keys import is_valid_key

        request = read_fixture("request.json")
        response = read_fixture("response.json")
        assert is_valid_key(request["public_key"])
        assert is_valid_key(response["hub_public_key"])

    def test_the_refresh_fixtures_have_matching_macs(self) -> None:
        request = read_fixture("refresh-request.json")
        response = read_fixture("refresh-response.json")
        key = refresh_key(join_mac_key(read_contract()["example_secret"]))
        assert request["mac"] == refresh_request_mac(key, request["name"], request["nonce"])
        assert response["mac"] == refresh_response_mac(
            key,
            request["nonce"],
            response["address"],
            response["hub_public_key"],
            response["hub_endpoint"],
            response["tunnel_network"],
            response["allowed_ips"],
            response["mtu"],
            response["keepalive"],
            response["protocol"],
            response["revision"],
        )


class TestTheGoModulesCopyIsHonest:
    """
    The Go module embeds a copy of these files so its test cache behaves.

    Go's test cache does not track a file outside the module, so a Go test that read
    `contracts/enrollment/` by path kept reporting a pass from cache after the contract
    changed. Embedding the files makes each one a build input and fixes that. The cost is
    a second copy, and the only thing stopping a second copy from becoming a second
    opinion is this class. pytest has no cache, so these checks cannot themselves go
    stale.
    """

    @pytest.mark.parametrize("name", MIRRORED_FILES)
    def test_the_copy_matches_byte_for_byte(self, name: str) -> None:
        canonical = (CONTRACT_DIR / name).read_bytes()
        mirrored = (MIRROR_DIR / name).read_bytes()
        assert mirrored == canonical, (
            f"node/internal/contract/{name} has drifted from contracts/enrollment/{name}. "
            f"Copy the canonical file over it: the Go tests read the copy, so until you do, "
            f"they are checking the Go structs against an old contract."
        )

    def test_the_copy_has_every_file_the_canonical_one_does(self) -> None:
        canonical = {path.name for path in CONTRACT_DIR.glob("*.json")}
        mirrored = {path.name for path in MIRROR_DIR.glob("*.json")}
        assert canonical == mirrored, (
            f"contracts/enrollment has {sorted(canonical)} and node/internal/contract has "
            f"{sorted(mirrored)}. Every fixture has to exist in both."
        )
        assert canonical == set(
            MIRRORED_FILES
        ), f"a fixture was added or removed without updating MIRRORED_FILES: {sorted(canonical)}"


def test_the_boot_service_refreshes_without_a_join_token() -> None:
    """An enrolled node boots straight into refresh.

    The service also carries the first-boot enrollment, because a packaged
    uci-defaults script makes OpenWrt's post-install run a bare ``uci commit``.
    A join only happens when there is no private key yet and a token is on
    disk, so a node that is already enrolled never needs one.
    """
    service = (REPO_ROOT / "packaging" / "openwrt" / "files" / "shadow9-node.init").read_text(
        encoding="utf-8"
    )
    assert '"$BINARY" refresh' in service
    assert "BINARY=/usr/sbin/shadow9-node" in service
    assert "if needs_enrollment; then" in service
    assert "network.$(saved_interface).private_key" in service
    assert '[ -s "$TOKEN" ]' in service


def test_the_package_ships_no_uci_defaults_script() -> None:
    """OpenWrt's default post-install runs a bare ``uci commit`` for any package
    that owns a uci-defaults script, which would commit an operator's pending
    changes. The boot service does the same first-boot enrollment instead."""
    packaging = REPO_ROOT / "packaging" / "openwrt"
    assert not list(
        (packaging / "files").glob("*shadow9-node")
    ), "a uci-defaults script is back in packaging/openwrt/files"
    makefile = (packaging / "Makefile").read_text(encoding="utf-8")
    assert "$(1)/etc/uci-defaults" not in makefile
