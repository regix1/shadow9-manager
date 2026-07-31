# The enrollment contract

The hub answers in Python and the node client parses in Go. Nothing catches a mismatch
between them at compile time, and the classic failure is the hub changing a required field
and a tunnel that comes up subtly wrong months later.

So the shapes live here as data rather than in either side's source, and both test suites
load these files:

| File | What it is |
|---|---|
| `fields.json` | Every field of the enrollment and refresh requests and responses, its type and whether it is required. This is the specification. |
| `request.json` | A worked example of what a node sends. |
| `response.json` | A worked example of what the hub answers. Its MAC covers the nonce in `request.json`. |
| `refresh-request.json` | A worked refresh request from the enrolled node in `request.json`. |
| `refresh-response.json` | A worked refresh answer. Its MAC covers the nonce in `refresh-request.json`. |
| `error.json` | The shape of a refused enrollment, one sentence under `detail`. The sentence is one the hub really sends. |

Read by `tests/test_wireguard_contract.py` (the models and the fixtures against each other),
`tests/test_wireguard_api.py` (what a running endpoint actually produces) and
`node/internal/enroll/contract_test.go`. **A field added on one side without the other fails
a test on both.** "It worked against a live hub" is not evidence, because a hub and a node
that drifted together still agree with each other.

## The mirror inside the Go module, and why it exists

`node/internal/contract/` holds a copy of the six JSON files, embedded into the Go package.
It exists for one reason: **Go's test cache does not track a file outside the module.** A Go
test that read these files by path went on reporting a stale pass after the contract changed,
which is exactly how this check decays without anyone noticing. Embedding makes each file a
build input, so changing one changes the package's build ID and the tests run again.

Both halves of that are verified rather than assumed. Adding a field to the embedded
`fields.json` makes `go test ./internal/enroll/` fail with no `-count=1`, and letting the copy
drift from this directory makes
`tests/test_wireguard_contract.py::TestTheGoModulesCopyIsHonest` fail and name the file.

The copy is not a second source of truth. This directory is canonical and is the only place
anyone edits. **If you change a file here, run `make -C node contract` in the same edit**, or
the Python guard will fail and tell you to.

## The exchange

`POST /api/wireguard/enroll`, 200 on success. **No admin API key is required or accepted**;
the join token is the credential. A node has to be able to join before anyone has given it
anything, and the alternative is shipping the admin key to every router that wants a tunnel.
`TestTheRouterIsWired::test_the_route_does_not_ask_for_an_api_key` asserts the OpenAPI
operation carries no `security` block, so this cannot be added by reflex.

The token is `<id>.<secret>.<hub-public-key>`. There is no older format to accept. The node
sends `token_id`, never the whole token or the secret. It derives the signing key as
`HMAC-SHA256(key=utf8(secret), message=b"shadow9-join-mac-v1")`. The hub stores that derived
key and finds it by id. Request and response MACs are lowercase hexadecimal HMAC-SHA256
values.

The node checks the response MAC before it writes any tunnel settings. It also compares the
key from the token with `hub_public_key` in the answer and writes nothing if they differ.
That second check stays because it is cheap and catches a different mistake.

The request MAC input is exactly these UTF-8 bytes. Every displayed line ends in `\n`,
including the last line. Routes keep the order sent and are joined with commas; no routes
means an empty value after `routes=`.

```
shadow9-join-request-v1
token_id=<token_id>
name=<name>
public_key=<public_key>
routes=<routes joined with "," in the order sent, empty string when there are none>
nonce=<nonce>
```

The response MAC input is exactly these UTF-8 bytes, again with `\n` after every line,
including the last one.

```
shadow9-join-response-v1
nonce=<the nonce from the request this answers>
address=<address>
hub_public_key=<hub_public_key>
hub_endpoint=<hub_endpoint>
tunnel_network=<tunnel_network>
mtu=<mtu>
keepalive=<keepalive>
protocol=<protocol>
```

`fields.json` carries an example secret only for checking the worked MACs in both test
suites. That example secret does not appear in `request.json`.

`routes` has a default of empty, so it may be left out, but it may not be `null`: a null is
not a list and comes back as a 422. A node with no LAN sends `[]`.

## Errors

Everything the hub itself refuses is one of these, with `detail` as a **string**:

| Status | When |
|---|---|
| 400 | The name, the public key or a route does not parse |
| 401 | The token id is unknown, expired or already spent, or the request MAC is wrong |
| 409 | That name is already a peer on this hub |
| 503 | This host is not serving a hub, has no endpoint set, or could not write its config |

A body that is not the right JSON shape at all is refused by pydantic first, as a **422**
whose `detail` is a **list of objects**. Those are the only two shapes a client handles.

## Refresh

`POST /api/wireguard/refresh`, 200 on success. No admin API key is required. A node saves
its name and a refresh key in the `shadow9` UCI package after enrollment. The refresh key
never crosses the network. Both sides derive it from the join MAC key:

```
refresh_key = HMAC-SHA256(key=mac_key_bytes, message=b"shadow9-refresh-v1")
```

The hub keeps that derived key on the peer's encrypted credential record. The node derives
the same bytes from the join token it already holds, then stores them only after the hub has
accepted enrollment. Someone watching the plain-HTTP join sees neither input key.

The refresh request MAC input is exactly these UTF-8 bytes, including the final `\n`:

```
shadow9-refresh-request-v1
name=<name>
nonce=<nonce>
```

The refresh response MAC input is exactly these UTF-8 bytes. `allowed_ips` keeps the order
the hub sends and is joined with commas. Every displayed line ends in `\n`, including the
last one.

```
shadow9-refresh-response-v1
nonce=<the nonce from the request this answers>
address=<address>
hub_public_key=<hub_public_key>
hub_endpoint=<hub_endpoint>
tunnel_network=<tunnel_network>
allowed_ips=<joined with ",">
mtu=<mtu>
keepalive=<keepalive>
protocol=<protocol>
revision=<revision>
```

Both sides compare MAC bytes in constant time. An unknown name and a bad MAC both return
401 with `This refresh request is not authorized.` The sentence deliberately does not say
whether the name exists.

`revision` is a hub-wide counter. It advances once when the recorded topology changes: a
peer is enrolled, removed, enabled or disabled, its advertised routes change, or the hub
endpoint changes. A node whose saved revision matches the signed answer writes nothing.
Otherwise it applies the whole signed answer through the same snapshot, commit, reload,
interface-check and rollback path used by enrollment.

## Response settings and version

`mtu` and `keepalive` are required integers from the hub's WireGuard settings. They are the
node defaults. A command-line `-mtu` or `-keepalive` value overrides the hub for that node;
`-keepalive 0` turns keepalives off. `protocol` is the required integer major version of
this exchange. This document defines protocol `1`; a node must refuse any other major
version before writing router configuration.

The token file now holds keys that can mint a join, where it used to hold one-way hashes.
Anyone able to read that file can already read the hub private key sitting beside it, which
is why keeping the derived keys there is acceptable. Someone on the path can still stop a
join from completing. That is denial of service, it is accepted, and this protocol does not
claim otherwise.

The node must still refuse a missing required field or a field with the wrong JSON type.
It ignores response fields it does not know, so a hub can add an optional field without
breaking routers that already understand the same protocol major version.

The remaining values are worked out as follows:

| Value | The node uses | Where the number comes from |
|---|---|---|
| DNS | none, unless the node wants a full tunnel | |
| The hub's tunnel address | the first usable address in `tunnel_network` | `wireguard_service.hub_address` |
| `AllowedIPs` on the hub peer | `tunnel_network` plus every enabled peer's advertised routes except this node's own | `wireguard.spoke_allowed_ips` |

A node pulls this complete list on refresh. Two site gateways therefore each route the
other site's LAN after both have refreshed. The hub still cannot push into a node whose
private key it has never held; the timing is explicit instead: a topology or endpoint change
reaches that node on its next manual refresh or boot refresh.
