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
shadow9 user generate --username myuser --password "MyP@ss!" --tor --bridge obfs4 --security moderate

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
  host: "127.0.0.1"          # bind address
  port: 1080                  # SOCKS5 port
  max_connections: 100
  connection_timeout: 30
  relay_timeout: 300
  buffer_size: 65536

tor:
  enabled: true
  socks_host: "127.0.0.1"
  socks_port: 9050
  control_port: 9051
  control_password: null
  auto_detect: true

auth:
  require_auth: true
  credentials_file: "config/credentials.enc"
  master_key_env: "SHADOW9_MASTER_KEY"
  session_timeout_hours: 24
  max_failed_attempts: 5
  lockout_duration_minutes: 15

log:
  level: "INFO"              # DEBUG, INFO, WARNING, ERROR
  format: "console"          # json or console
  file: null
  max_size_mb: 10
  backup_count: 3

security:
  allowed_ports: [80, 443, 8080, 8443]
  blocked_hosts: []
  allow_localhost: false
  rate_limit_per_minute: 100
  max_request_size: 1048576
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `SHADOW9_MASTER_KEY` | Encryption key for credentials |
| `SHADOW9_HOME` | Base directory for Shadow9 |
| `SHADOW9_HOST` | Server bind address |
| `SHADOW9_PORT` | Server port |
| `SHADOW9_TOR_ENABLED` | Enable Tor routing |
| `SHADOW9_TOR_PORT` | Tor SOCKS port |
| `SHADOW9_LOG_LEVEL` | Log level |

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
| `--ports` | `"80,443"` or `"all"` | `all` |
| `--rate-limit` | integer | unlimited |
| `--bind-port` | port number | shared (1080) |

**Example:**
```bash
shadow9 user generate \
  --username secureuser \
  --password "ComplexP@ss!" \
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
│   └── Service commands (install, start, stop, logs)
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
    ├── Rate limiting
    └── Port/host restrictions
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
- **Host blocking** — block specific destination hosts
- **Rate limiting** — per-user request limits
- **Account lockout** — automatic lockout after failed auth attempts

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

**Diagnostic commands:**
```bash
shadow9 check-tor              # check Tor connectivity
shadow9 service status         # view service status
shadow9 service logs -f        # follow logs
SHADOW9_LOG_LEVEL=DEBUG shadow9 serve  # verbose output
```

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
