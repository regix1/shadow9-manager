"""
Request and response schemas for WireGuard enrollment and refresh.

This is a contract between two languages: the hub answers in Python and the node client
parses in Go. Nothing catches a mismatch at compile time, so the field names and types here
are fixed by test fixtures both sides load rather than by either side's convenience.

The response carries the address, hub connection details, tunnel settings and protocol
major version. **No private key ever appears in a response**: a node generates its own
keypair and sends only the public half, so the hub has never held the secret it would
otherwise be tempted to send back.

Refresh uses a separately derived key and returns the complete current route list plus the
hub-wide topology revision. That key is stored on each side and is never a wire field.

The body is checked here for shape only. Whether a key is really a key, a name is usable
and a route is a route is decided in the service, so those come back as a 400 with one
sentence rather than as pydantic's field-by-field 422. A Go client therefore has two error
shapes to handle and not one per field.
"""

from pydantic import BaseModel, ConfigDict, Field


class EnrollmentRequest(BaseModel):
    """What a node sends to join the tunnel."""

    model_config = ConfigDict(extra="forbid")

    token_id: str = Field(
        ...,
        description="The public id of the join token being spent.",
    )
    name: str = Field(
        ...,
        description="The peer name, 3 to 64 letters, digits, underscores or hyphens.",
    )
    public_key: str = Field(
        ...,
        description=(
            "The node's base64 X25519 public key, 44 characters. The node keeps the "
            "private half; this hub never sees it."
        ),
    )
    routes: list[str] = Field(
        default_factory=list,
        description=(
            "Subnets behind this node in CIDR form, which makes it a site gateway. Every "
            "other peer routes these into the tunnel."
        ),
    )
    nonce: str = Field(..., description="A fresh random value for this enrollment attempt.")
    mac: str = Field(..., description="The HMAC-SHA256 signature of this request.")


class EnrollmentResponse(BaseModel):
    """What the hub answers a node that joined."""

    model_config = ConfigDict(extra="forbid")

    address: str = Field(
        ...,
        description="The tunnel address this peer was given, with no prefix, e.g. 10.9.0.2",
    )
    hub_public_key: str = Field(
        ...,
        description=(
            "The hub's base64 public key. The node compares this with the key half of its "
            "token and writes nothing if the two differ."
        ),
    )
    hub_endpoint: str = Field(
        ...,
        description="The `host:port` this peer should dial, e.g. 203.0.113.10:51820",
    )
    tunnel_network: str = Field(
        ...,
        description="The range the tunnel covers in CIDR form, e.g. 10.9.0.0/24",
    )
    mtu: int = Field(..., description="The interface MTU the node must apply")
    keepalive: int = Field(
        ..., description="Seconds between node keepalives, or 0 to turn them off"
    )
    protocol: int = Field(..., description="The enrollment protocol major version")
    mac: str = Field(..., description="The HMAC-SHA256 signature of this answer")


class RefreshRequest(BaseModel):
    """What an enrolled node sends to pull current tunnel settings."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="The peer name saved when this node enrolled")
    nonce: str = Field(..., description="A fresh random value for this refresh attempt")
    mac: str = Field(..., description="The HMAC-SHA256 signature of this request")


class RefreshResponse(BaseModel):
    """The complete tunnel settings an enrolled node should apply."""

    model_config = ConfigDict(extra="forbid")

    address: str = Field(..., description="The node's assigned tunnel address")
    hub_public_key: str = Field(..., description="The hub's WireGuard public key")
    hub_endpoint: str = Field(..., description="The host and port this node should dial")
    tunnel_network: str = Field(..., description="The tunnel range in CIDR form")
    allowed_ips: list[str] = Field(
        ...,
        description="Every range this node should route through the hub, in order",
    )
    mtu: int = Field(..., description="The interface MTU the node must apply")
    keepalive: int = Field(..., description="Seconds between keepalives, or zero")
    protocol: int = Field(..., description="The refresh protocol major version")
    revision: int = Field(..., description="The hub topology revision")
    mac: str = Field(..., description="The HMAC-SHA256 signature of this answer")
