"""
WireGuard enrollment and refresh endpoints.

**This endpoint is authenticated by the join token, not by the admin API key.** That is
deliberate: a node has to be able to join before anyone has given it anything, and the
alternative would be shipping the admin key to every router that wants a tunnel, which is a
far worse trade than a single-use secret that expires. The token is spent by the first call
that uses it and refused after that.

The hub is a bare IP over plain HTTP. The request MAC covers the node key and every other
request field, and the response MAC covers the assigned settings and the request nonce.
The node verifies the response before writing anything, then also compares the answer's
hub key with the key in its token. Someone on the path can still stop the join.

The response never carries a private key. A node generates its own keypair and sends the
public half, so there is no private WireGuard key here to leak back.

After enrollment, a node authenticates refresh with a key both sides derived from the join
MAC key. It pulls current routes and endpoint settings because the hub has never held the
node's private WireGuard key and cannot push a replacement config to it.
"""

import asyncio

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse

from ...auth import AuthManager
from ...config import Config
from ...schemas.wireguard import (
    EnrollmentRequest,
    EnrollmentResponse,
    RefreshRequest,
    RefreshResponse,
)
from ...services.wireguard_service import (
    NODE_ARCHITECTURES,
    NODE_CHECKSUM_FILE,
    NODE_PACKAGE_FILES,
    NODE_RELEASE_URL,
    ENROLLMENT_PROTOCOL,
    Enrollment,
    PeerFieldsMissing,
    Refresh,
    RefreshRejected,
    TokenRejected,
    enroll_peer,
    hub_public_key,
    node_binary_path,
    node_checksum_path,
    node_package_checksum_path,
    node_package_path,
    refresh_peer,
    refresh_response_mac,
    response_mac,
)
from ..deps import get_auth_manager, get_config

router = APIRouter(prefix="/wireguard", tags=["wireguard"])


@router.post(
    "/enroll",
    response_model=EnrollmentResponse,
    status_code=status.HTTP_200_OK,
    summary="Join this hub's tunnel with a join token",
    responses={
        200: {"description": "Enrolled. The answer names the address given and the hub key"},
        400: {"description": "The name, public key or a route is not usable"},
        401: {"description": "The join token is unknown, expired or spent, or the MAC is wrong"},
        409: {"description": "That name is already a peer on this hub"},
        503: {"description": "This host is not serving a WireGuard hub yet"},
    },
)
async def enroll(
    request: EnrollmentRequest,
    cfg: Config = Depends(get_config),
    auth_manager: AuthManager = Depends(get_auth_manager),
) -> EnrollmentResponse:
    """
    Enrol a node and return what it needs to build its side of the tunnel.

    - **token_id**: the public id of the join token spent by this call
    - **name**: the peer name, 3 to 64 letters, digits, underscores or hyphens
    - **public_key**: the node's base64 X25519 public key. The private half stays on the node
    - **routes**: subnets behind this node, which makes it a site gateway
    - **nonce**: a fresh random value for this attempt
    - **mac**: the signature covering every request field

    No admin API key is required or accepted here. The token is the credential.
    """
    if not cfg.wireguard.enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "WireGuard is turned off on this hub. Run 'shadow9 wg init' on the hub, or "
                "set wireguard.enabled in config/config.yaml."
            ),
        )

    if hub_public_key() is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="This host has no WireGuard hub key yet. Run 'shadow9 wg init' on the hub.",
        )

    if not cfg.wireguard.hub_endpoint:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "This hub has no endpoint set, so a node would have nothing to dial. Run "
                "'shadow9 wg hub set-endpoint <address:port>' on the hub."
            ),
        )

    try:
        enrollment: Enrollment = await asyncio.to_thread(
            enroll_peer,
            cfg,
            auth_manager,
            request.token_id,
            request.name,
            request.public_key,
            request.routes,
            request.nonce,
            request.mac,
        )
    except TokenRejected as error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(error)) from error
    except PeerFieldsMissing as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(error)
        ) from error
    except ValueError as error:
        # A name that is already enrolled is the one conflict a caller can fix by picking
        # another name, so it is worth telling apart from a key that does not parse
        code = (
            status.HTTP_409_CONFLICT
            if "already a peer" in str(error)
            else status.HTTP_400_BAD_REQUEST
        )
        raise HTTPException(status_code=code, detail=str(error)) from error
    except OSError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"The hub could not complete enrollment: {error}",
        ) from error

    address = str(enrollment.peer.address)
    hub_key = enrollment.topology.hub.public_key
    endpoint = enrollment.topology.hub.endpoint or cfg.wireguard.hub_endpoint
    network = str(enrollment.topology.tunnel_network)
    mac = response_mac(
        enrollment.token.mac_key,
        request.nonce,
        address,
        hub_key,
        endpoint,
        network,
        cfg.wireguard.mtu,
        cfg.wireguard.keepalive,
        ENROLLMENT_PROTOCOL,
    )
    return EnrollmentResponse(
        address=address,
        hub_public_key=hub_key,
        hub_endpoint=endpoint,
        tunnel_network=network,
        mtu=cfg.wireguard.mtu,
        keepalive=cfg.wireguard.keepalive,
        protocol=ENROLLMENT_PROTOCOL,
        mac=mac,
    )


@router.post(
    "/refresh",
    response_model=RefreshResponse,
    status_code=status.HTTP_200_OK,
    summary="Pull the current tunnel settings for an enrolled node",
    responses={
        200: {"description": "The complete current settings for this node"},
        401: {"description": "The peer name or request MAC is not accepted"},
        503: {"description": "This host is not serving a WireGuard hub yet"},
    },
)
async def refresh(
    request: RefreshRequest,
    cfg: Config = Depends(get_config),
    auth_manager: AuthManager = Depends(get_auth_manager),
) -> RefreshResponse:
    """Authenticate an enrolled node and return its complete current route list."""
    if not cfg.wireguard.enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="WireGuard is turned off on this hub.",
        )
    if hub_public_key() is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="This host has no WireGuard hub key yet. Run 'shadow9 wg init' on the hub.",
        )
    if not cfg.wireguard.hub_endpoint:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="This hub has no endpoint set, so a node would have nothing to dial.",
        )

    try:
        refreshed: Refresh = await asyncio.to_thread(
            refresh_peer,
            cfg,
            auth_manager,
            request.name,
            request.nonce,
            request.mac,
        )
    except RefreshRejected as error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(error)) from error
    except (ValueError, OSError) as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"The hub could not refresh this node: {error}",
        ) from error

    address = str(refreshed.peer.address)
    hub_key = refreshed.topology.hub.public_key
    endpoint = refreshed.topology.hub.endpoint or cfg.wireguard.hub_endpoint
    network = str(refreshed.topology.tunnel_network)
    allowed_ips = list(refreshed.allowed_ips)
    mac = refresh_response_mac(
        refreshed.refresh_key,
        request.nonce,
        address,
        hub_key,
        endpoint,
        network,
        allowed_ips,
        cfg.wireguard.mtu,
        cfg.wireguard.keepalive,
        ENROLLMENT_PROTOCOL,
        refreshed.revision,
    )
    return RefreshResponse(
        address=address,
        hub_public_key=hub_key,
        hub_endpoint=endpoint,
        tunnel_network=network,
        allowed_ips=allowed_ips,
        mtu=cfg.wireguard.mtu,
        keepalive=cfg.wireguard.keepalive,
        protocol=ENROLLMENT_PROTOCOL,
        revision=refreshed.revision,
        mac=mac,
    )


@router.get(
    "/node/" + NODE_CHECKSUM_FILE,
    summary="The checksums of the node client builds",
    response_class=FileResponse,
    responses={
        200: {"description": "One line per architecture, as sha256sum writes them"},
        404: {"description": "The binaries have not been built on this hub"},
    },
)
async def node_checksums() -> FileResponse:
    """
    Serve the recorded checksums of the node client builds.

    Served over the same unauthenticated plain HTTP as the binaries, so on its own this
    proves nothing: whoever could swap a binary could swap this too. It is useful because
    the hub prints the same checksums on its own terminal, where the operator reads them
    before going anywhere near the router. That is the same trick the join token plays with
    the hub's public key, and it is the only one available without TLS.
    """
    path = node_checksum_path()
    if path is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "This hub has no recorded checksums for the node client. Run "
                "'make -C node checksums' where shadow9 is installed."
            ),
        )

    return FileResponse(path, media_type="text/plain", filename=NODE_CHECKSUM_FILE)


@router.get(
    "/node/package/" + NODE_CHECKSUM_FILE,
    summary="The checksums of the OpenWrt node packages",
    response_class=FileResponse,
    responses={
        200: {"description": "One line per package, as sha256sum writes them"},
        404: {"description": "The packages are not stored on this hub"},
    },
)
async def node_package_checksums() -> FileResponse:
    """Serve checksums for the OpenWrt packages collected by CI."""
    path = node_package_checksum_path()
    if path is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "This hub has no recorded checksums for OpenWrt packages. A git clone does "
                f"not include CI packages; get them from {NODE_RELEASE_URL}."
            ),
        )

    return FileResponse(path, media_type="text/plain", filename=NODE_CHECKSUM_FILE)


@router.get(
    "/node/package/{package}/{architecture}",
    summary="Download an OpenWrt node package",
    response_class=FileResponse,
    responses={
        200: {"description": "The matching ipk or apk package"},
        404: {"description": "The package is not supported or is not stored on this hub"},
    },
)
async def node_package(package: str, architecture: str) -> FileResponse:
    """Serve an allowlisted OpenWrt package from node/packages."""
    path = node_package_path(package, architecture)
    if path is None:
        if package not in NODE_PACKAGE_FILES or architecture not in NODE_ARCHITECTURES:
            detail = (
                f"There is no '{package}' node package for '{architecture}'. The supported "
                f"formats are {', '.join(NODE_PACKAGE_FILES)} and the supported architectures "
                f"are {', '.join(NODE_ARCHITECTURES)}."
            )
        else:
            detail = (
                f"This hub does not have the {package} node package for '{architecture}'. "
                "Packages are CI release files and are not included in a git clone. Get the "
                f"matching package from {NODE_RELEASE_URL}."
            )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)

    return FileResponse(path, media_type="application/octet-stream", filename=path.name)


@router.get(
    "/node/linux-{architecture}",
    summary="Download the node client for one architecture",
    response_class=FileResponse,
    responses={
        200: {"description": "The static binary, as an octet stream"},
        404: {"description": "Not an architecture this project builds, or not built here"},
    },
)
async def node_binary(architecture: str) -> FileResponse:
    """
    Serve the cross-compiled node client, so a router needs no package feed.

        wget -O /usr/sbin/shadow9-node http://<hub>:8081/api/wireguard/node/linux-$architecture
        chmod +x /usr/sbin/shadow9-node

    A router names the same hardware differently from Go: `x86_64` is `amd64`, `aarch64` is
    `arm64`, `mipsel` is `mipsle`.

    **No admin API key, deliberately.** A router that has not enrolled holds no credential,
    and the admin key travels in cleartext over this same plain HTTP, so putting it in a
    `wget` URL typed on a router would spread the more dangerous secret to fetch the less
    dangerous file. The binary is a build artifact rather than a secret. What the operator
    gets instead is a checksum printed on the hub's terminal, which is checkable without
    trusting the network.
    """
    path = node_binary_path(architecture)
    if path is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"This hub does not serve a node client for 'linux-{architecture}'. It "
                f"builds {', '.join(NODE_ARCHITECTURES)}. If the architecture is right, "
                f"run 'make -C node dist' where shadow9 is installed."
            ),
        )

    return FileResponse(path, media_type="application/octet-stream", filename=path.name)
