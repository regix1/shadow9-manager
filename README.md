# Shadow9 Manager

A multi-user SOCKS5 proxy server with Tor routing, pluggable transport support, and DPI bypass capabilities.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Configuration](#configuration)
- [User Settings](#user-settings)
- [Architecture](#architecture)
- [Security Features](#security-features)
- [Performance](#performance)
- [Troubleshooting](#troubleshooting)
- [Breaking Changes](#breaking-changes)
- [Development](#development)
- [License](#license)

---

## Overview

Shadow9 routes SOCKS5 traffic through the Tor network with per-user settings. Each user gets isolated Tor circuits, optional bridge support for censored networks, and configurable DPI evasion levels.

- **RFC 1928/1929 compliant** — full SOCKS5 implementation with username/password auth
- **Per-user Tor routing** — isolated circuits for each user
- **Pluggable transports** — obfs4 and Snowflake bridges when Tor is blocked
- **DPI bypass** — TLS splitting, SNI fragmentation, timing jitter
- **Dedicated ports** — optional per-user listening ports
- **Bridge speed testing** — automatic ranking and selection of fastest bridges
- **Systemd integration** — native Linux service management

---

## Features

<details>
<summary><strong>Core Proxy</strong></summary>

- **SOCKS5 server** — RFC 1928 protocol with RFC 1929 authentication
- **Multi-user support** — individual accounts with encrypted credential storage
- **Per-user routing** — each user can have different Tor and security settings
- **Dedicated ports** — optional per-user listening ports for isolation

</details>

<details>
<summary><strong>Tor Integration</strong></summary>

- **Tor network routing** — traffic goes through Tor for anonymity
- **Per-user circuits** — isolated Tor circuits per user
- **Bridge support** — obfs4 and Snowflake for blocked networks
- **Smart bridge selection** — speed tests bridges at startup, uses the fastest
- **Conflux support** — multi-path routing for better performance (Tor 0.4.8+)

</details>

<details>
<summary><strong>Security & Privacy</strong></summary>

- **DPI bypass** — multiple evasion levels for deep packet inspection
- **Argon2id hashing** — secure password storage
- **Fernet encryption** — AES-128 for stored credentials
- **Rate limiting** — per-user request limits
- **Port restrictions** — configurable allowed destination ports
- **Account lockout** — protection against brute-force attempts
- **Internal address blocking** — private and loopback destinations are refused by default

</details>

<details>
<summary><strong>Operations</strong></summary>

- **Systemd integration** — native Linux service management
- **Structured logging** — JSON or console output with configurable levels
- **Interactive wizards** — guided setup for users and configuration
- **Hot reload** — user credentials reload without server restart

</details>

---

## Requirements

- **Python** — 3.10 or higher
- **OS** — Linux, macOS, or Windows
- **Tor** — 0.4.8+ recommended for Conflux support
- **Pluggable transports** — obfs4proxy and snowflake-client (optional, for bridges)

---

## Installation

### Clone the repository

```bash
git clone https://github.com/regix1/shadow9-manager.git
cd shadow9-manager
```

### Install Shadow9

**Linux/macOS:**
```bash
chmod +x setup shadow9
./setup
```

**Windows:**
```cmd
setup.bat
```

### Install Tor and pluggable transports (optional)

```bash
shadow9 setup
```

This wizard installs Tor 0.4.8+ from the official repository and configures pluggable transports.

---

## Quick Start

```bash
# Install Shadow9
./setup

# (Optional) Install Tor and bridges
shadow9 setup

# Create a user
shadow9 user generate

# Start the server
shadow9 serve
```

Connect your SOCKS5 client to `127.0.0.1:1080` with your credentials.

### Binding and network exposure

The server binds to `127.0.0.1` by default, so it only accepts connections from the same
machine. `shadow9 service install` defaults the same way, so a service installed with no
flags is also local-only. Exposing the proxy to your network is now something you ask for
explicitly:

```bash
shadow9 serve --host 0.0.0.0                    # this run only
sudo shadow9 service install --host 0.0.0.0     # bake it into the systemd unit
```

Or set `server.host: "0.0.0.0"` in `config/config.yaml`.

The default used to be `0.0.0.0`. Listening on every interface meant an unauthenticated
stranger could open connections to the proxy, and each one costs 64 MB during password
hashing, so a machine could be pushed out of memory from the outside. Binding to loopback
means only local clients can reach it. If you do open it up, put it behind a firewall rule
that limits which addresses can connect.

---

## Usage

### Server Commands

```bash
# Start the server
shadow9 serve

# Start with custom host/port
shadow9 serve --host 0.0.0.0 --port 8080

# Stop a running server
shadow9 stop
```

### User Management

```bash
# Generate a new user (interactive)
shadow9 user generate

# Generate with options
shadow9 user generate --username myuser --password "Str0ngP@ssw0rd!" --tor --bridge obfs4 --security moderate

# List users
shadow9 user list

# List with details
shadow9 user list -i

# View user details
shadow9 user info <username>

# Modify user settings
shadow9 user modify <username>

# Enable/disable a user
shadow9 user enable <username>
shadow9 user disable <username>

# Remove a user
shadow9 user remove <username>
```

Passwords you supply with `--password` must be at least 12 characters and contain an
uppercase letter, a lowercase letter, a digit and a special character. Omit the flag
to get a generated password that already meets those rules.

`--ports` and `--bind-port` accept 1-65535, and `--rate-limit` accepts 1 or more.
On `shadow9 user modify`, `--rate-limit 0` and `--bind-port 0` mean "go back to the
server default".

### Interactive Menu

```bash
# Open the menu (this is also what runs when shadow9 is called with no arguments)
shadow9 menu
```

### Encryption Keys

```bash
# Create the master key that encrypts the credentials file
shadow9 key generate

# Regenerate it (this invalidates every existing credential)
shadow9 key generate --force

# Report whether a master key is configured
shadow9 key check
```

### REST API

The API is a separate process from the proxy. It needs `SHADOW9_API_KEY` set;
every endpoint returns 503 without it.

```bash
# Write config/api.yaml and create an API key
shadow9 api setup

# Run the API server
shadow9 api start

# Show the API configuration and whether the server answers
shadow9 api status

# Show or rotate the stored API key
shadow9 api key
```

### Service Management (Linux)

```bash
# Install the service
sudo shadow9 service install

# Start/stop/restart
sudo shadow9 service start
sudo shadow9 service stop
sudo shadow9 service restart

# Check status
shadow9 service status

# View logs
shadow9 service logs          # all logs
shadow9 service logs -f       # follow in real-time
shadow9 service logs -c       # current run only

# Enable/disable auto-start
sudo shadow9 service enable
sudo shadow9 service disable

# Uninstall
sudo shadow9 service uninstall
```

### Diagnostics

```bash
# Run the Tor setup wizard
shadow9 setup

# Check Tor connectivity
shadow9 check-tor
```

---

## Configuration

### Configuration File

Located at `config/config.yaml`:

```yaml
server:
  host: "127.0.0.1"          # bind address, local-only by default
  port: 1080                  # SOCKS5 port
  max_connections: 100        # connections accepted at once
  connection_timeout: 30      # seconds

tor:
  enabled: true
  socks_host: "127.0.0.1"
  socks_port: 9050
  control_port: 9051
  control_password: null

auth:
  require_auth: true
  credentials_file: "config/credentials.enc"
  max_failed_attempts: 5      # failures before the account is locked
  lockout_duration_minutes: 15

log:
  level: "INFO"              # DEBUG, INFO, WARNING, ERROR
  format: "console"          # json or console
  file: null
  max_size_mb: 10
  backup_count: 3

security:
  allowed_ports: [80, 443, 8080, 8443]
  block_private_ranges: true  # refuse private and loopback destinations
  allow_localhost: false      # exception to the above for 127.0.0.0/8
  rate_limit_per_minute: 100  # default when a user has no rate limit set
```

Every key above is read by the server. The master key is always taken from the
`SHADOW9_MASTER_KEY` environment variable and is not configurable from this file.

### Environment Variables

Read by the proxy (`shadow9 serve`):

| Variable | Description |
|----------|-------------|
| `SHADOW9_MASTER_KEY` | Encryption key for credentials |
| `SHADOW9_HOME` | Base directory for Shadow9 |
| `SHADOW9_HOST` | Server bind address |
| `SHADOW9_PORT` | Server port |
| `SHADOW9_TOR_ENABLED` | Enable Tor routing |
| `SHADOW9_TOR_PORT` | Tor SOCKS port |
| `SHADOW9_LOG_LEVEL` | Log level |

Read by the API (`shadow9 api start`):

| Variable | Description |
|----------|-------------|
| `SHADOW9_API_KEY` | Required. Every endpoint returns 503 until this is set |
| `SHADOW9_CORS_ORIGINS` | Comma-separated allowed origins. Empty means CORS is off |
| `SHADOW9_HOST`, `SHADOW9_PORT` | Server bind address and port |
| `SHADOW9_TOR_SOCKS_PORT` | Tor SOCKS port. The API uses this name, not `SHADOW9_TOR_PORT` |
| `SHADOW9_MASTER_KEY` | Encryption key for credentials |

---

## User Settings

### Security Levels

| Level | Description |
|-------|-------------|
| `none` | Raw forwarding, maximum speed |
| `basic` | Standard protection |
| `moderate` | Header randomization, timing jitter |
| `paranoid` | Full evasion, decoy traffic |

### Bridge Types

| Bridge | Description |
|--------|-------------|
| `none` | Direct Tor connection |
| `obfs4` | Obfuscated traffic that looks random |
| `snowflake` | WebRTC-based transport using volunteer proxies |

Shadow9 manages separate Tor instances per bridge type — direct on 9050, obfs4 on 9051, snowflake on 9052. Users route through their configured bridge automatically.

### Per-User Options

| Option | Values | Default |
|--------|--------|---------|
| `--tor/--no-tor` | — | `--tor` |
| `--bridge` | `none`, `obfs4`, `snowflake` | `none` |
| `--security` | `none`, `basic`, `moderate`, `paranoid` | `basic` |
| `--ports` | `"80,443"` (each 1-65535) or `"all"` | `all` |
| `--rate-limit` | requests per minute, 1 or more | server default |
| `--bind-port` | 1-65535 | shared (1080) |
| `--logging/--no-logging` | — | `--logging` |

**Example:**
```bash
shadow9 user generate \
  --username secureuser \
  --password "Str0ngP@ssw0rd!" \
  --tor \
  --bridge snowflake \
  --security paranoid \
  --ports "80,443" \
  --rate-limit 60 \
  --bind-port 1081
```

---

## Architecture

### Component Overview

```
Shadow9 Manager
├── CLI (Typer + Rich)
│   ├── Server commands (serve, stop)
│   ├── User commands (generate, list, modify, remove)
│   ├── Service commands (install, start, stop, logs)
│   ├── Key commands (generate, check)
│   ├── API commands (setup, start, status, key)
│   └── Interactive menu
├── REST API (FastAPI, separate process)
│   ├── User endpoints (list, create, modify, remove)
│   ├── Server status endpoints
│   └── API key authentication
├── SOCKS5 Server
│   ├── RFC 1928/1929 protocol handler
│   ├── User authentication (Argon2id)
│   ├── Per-user port listeners
│   └── Connection relay
├── Tor Integration
│   ├── TorConnector (connection management)
│   ├── TorBridgeConnector (bridge support)
│   └── PluggableTransportManager (obfs4, snowflake)
└── Security Layer
    ├── DPI bypass (TLS splitting, SNI fragmentation)
    ├── Rate limiting and account lockout
    └── Port and internal-address restrictions
```

### Data Flow

```
Client → SOCKS5 Handshake → Authentication → User Resolution → Security Layer → Tor Routing → Destination
```

---

## Security Features

<details>
<summary><strong>Credential Security</strong></summary>

- **Password hashing** — Argon2id with secure parameters
- **Encryption at rest** — Fernet (AES-128-CBC) for stored credentials
- **Master key** — environment-based key management

</details>

<details>
<summary><strong>DPI Bypass Techniques</strong></summary>

- **TLS Client Hello splitting** — fragments handshakes to evade pattern matching
- **SNI fragmentation** — splits Server Name Indication across packets
- **HTTP request modification** — randomizes headers and request patterns
- **Timing jitter** — random delays to defeat timing analysis
- **Decoy traffic** — fake traffic to mask real patterns (paranoid mode)

</details>

<details>
<summary><strong>Access Control</strong></summary>

- **Per-user port restrictions** — limit which ports users can connect to
- **Internal address blocking** — private and loopback destinations are refused after
  DNS resolution, so a hostname pointing at an internal address is blocked too.
  Set `security.allow_localhost: true` to permit loopback
- **Rate limiting** — per-user request limits, from the user's `--rate-limit` or
  `security.rate_limit_per_minute`
- **Account lockout** — an account is locked after `auth.max_failed_attempts`
  failures for `auth.lockout_duration_minutes`

</details>

---

## Performance

- **Conflux multi-path** — splits traffic across two Tor circuits for ~30% faster downloads (Tor 0.4.8+)
- **Bridge speed testing** — tests all bridges at startup, ranks by performance, uses the fastest
- **Connection padding** — traffic analysis resistance with optimized circuit parameters

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Bridges not connecting | Run `shadow9 setup` to upgrade to Tor 0.4.8+ |
| Authentication failures | Check credentials, verify user is enabled |
| Connection timeouts | Run `shadow9 check-tor` to diagnose |
| Permission denied | Use `sudo` for service commands |
| Port already in use | Change port in config or stop conflicting service |
| Users disappear after a change | A `.lock` file was deleted while Shadow9 was running, see below |

**Do not delete `*.lock` files while Shadow9 is running.** Shadow9 keeps a small empty
`.lock` file beside `credentials.enc` and beside the key salt, and uses it to stop the
proxy and the API changing the same file at once. On Linux the lock belongs to the open
file rather than to the name, so removing one while it is held lets two processes edit
the credentials at the same time and one of them silently overwrites the other's users.
Nothing can detect that after the fact. Stop the service first; with Shadow9 stopped
these files are safe to delete and are recreated on the next start.

**Diagnostic commands:**
```bash
shadow9 check-tor              # check Tor connectivity
shadow9 service status         # view service status
shadow9 service logs -f        # follow logs
SHADOW9_LOG_LEVEL=DEBUG shadow9 serve  # verbose output
```

---

## Breaking Changes

A cleanup pass removed code that nothing in this repository called. If you only use the
`shadow9` command line or the REST API, nothing here affects you. If you import `shadow9`
from your own Python, read this list. The package version has not been raised yet, so
`shadow9.__version__` still reports `1.0.0` and cannot be used to tell the two apart.

**Configuration**

`auth.session_timeout_hours` is gone. Nothing honored it once the session service was
removed, and the loader warned about it on every start. It has been taken out of the
shipped `config/config.yaml`; delete it from your own config to stop the warning. Every
other `auth` setting is unchanged.

**Removed names that were published in `__all__`**

| Was | Now |
|-----|-----|
| `shadow9.services.AuthService` | removed, no replacement. The whole `shadow9.services.auth_service` module is gone. |
| `shadow9.api.get_auth_service` | removed, no replacement. It only ever built the class above. |
| `shadow9.core.setup_logging` | moved. Import `setup_logging` from `shadow9.config` instead. |

**Removed classes and functions**

None of these had callers, and none has a replacement.

| Was | Kind |
|-----|------|
| `shadow9.auth.SessionManager` | in-memory session tracking nothing consulted |
| `shadow9.services.auth_service.Session` | went with the module above |
| `shadow9.security.SecureServer`, `SecureTransport`, `TLSWrapper` | an unused TLS layer |
| `shadow9.security.print_security_info` | console helper |
| `shadow9.socks5_client.Socks5ClientPool`, `connect_via_socks5` | an unused client pool |
| `shadow9.schemas.common.PaginatedResponse` | the API returns its own shapes |
| `shadow9.logging_utils.create_user_logger` | console helper |
| `shadow9.bridges.print_bridge_info` | console helper |
| `shadow9.wizards.user_info.run_user_info_wizard` | console helper |

---

## Development

```bash
# Clone and setup
git clone https://github.com/regix1/shadow9-manager.git
cd shadow9-manager
python -m venv venv
source venv/bin/activate  # Linux/macOS
pip install -e ".[dev]"

# Run tests
pytest tests/

# Code style
black src/       # format
mypy src/        # type check
ruff check src/  # lint
```

---

## License

MIT License. See LICENSE file for details.

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request
