# Shadow9 Manager

Secure SOCKS5 proxy with Tor routing, per-user settings, and DPI bypass.

## Features

- **SOCKS5 Proxy** - RFC 1928/1929 compliant
- **Per-User Tor Routing** - Isolated circuits per user
- **Bridge Support** - obfs4, snowflake for censorship bypass
- **Conflux** - Multi-path routing (~30% speed boost)
- **Smart Bridge Selection** - Auto speed-test and ranking
- **DPI Bypass** - Multiple evasion levels
- **Per-User Ports** - Dedicated listeners

## Quick Start

```bash
git clone https://github.com/regix1/shadow9-manager.git
cd shadow9-manager
chmod +x setup shadow9
./setup              # Install shadow9
shadow9 setup        # Install Tor + bridges (optional)
shadow9 user generate
shadow9 serve
```

Connect to `127.0.0.1:1080` with your credentials.

## Installation

### Two-Phase Setup

1. `./setup` - Installs shadow9 CLI and dependencies
2. `shadow9 setup` - Installs Tor 0.4.8+ and pluggable transports from official Tor Project repo

### Why Tor 0.4.8+?

Required for Conflux multi-path support and modern bridge protocols.

## Commands

```bash
# Server
shadow9 serve
shadow9 serve --host 0.0.0.0 --port 8080

# Users
shadow9 user generate
shadow9 user list [-i]
shadow9 user info <user>
shadow9 user modify <user>
shadow9 user remove <user>
shadow9 user enable|disable <user>

# Service (Linux)
sudo shadow9 service install
sudo shadow9 service start|stop|restart|status
shadow9 service logs [-f] [-c]    # -c = current run only

# Setup
shadow9 setup                     # Install Tor + bridges
shadow9 check-tor
```

## User Options

```bash
shadow9 user generate --username myuser --password "MyP@ss!" \
  --tor --bridge snowflake --security basic
```

| Option | Values | Default |
|--------|--------|---------|
| `--tor/--no-tor` | - | tor |
| `--bridge` | none, obfs4, snowflake | none |
| `--security` | none, basic, moderate, paranoid | basic |
| `--ports` | "80,443" or "all" | all |
| `--rate-limit` | requests/min | unlimited |
| `--bind-port` | dedicated port | shared |

### Security Levels

| Level | Effect |
|-------|--------|
| none | Raw SOCKS5, max speed |
| basic | Standard protection |
| moderate | Header randomization, timing jitter |
| paranoid | Full evasion, decoy traffic |

### Bridge Types

| Bridge | Use Case |
|--------|----------|
| none | Unrestricted networks |
| obfs4 | Tor blocked by ISP |
| snowflake | Heavy censorship |

## Performance

### Conflux (Tor 0.4.8+)

Splits traffic across two circuits. ~30% faster downloads.

### Bridge Speed Testing

Auto-tests all bridges at startup, ranks by speed, connects via fastest.

### Tor Optimizations

Extended timeouts, connection padding, hidden service tuning applied automatically.

## Architecture

```
Tor Instances (auto-managed):
  none:      127.0.0.1:9050
  obfs4:     127.0.0.1:9051
  snowflake: 127.0.0.1:9052

Users route through their configured bridge type.
```

## Configuration

**File:** `config/config.yaml`

```yaml
server:
  host: "0.0.0.0"
  port: 1080
tor:
  socks_port: 9050
  control_port: 9051
```

**Environment:**
- `SHADOW9_MASTER_KEY` - Credential encryption key
- `SHADOW9_HOME` - Base directory

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Bridges failing | Run `shadow9 setup` to upgrade Tor to 0.4.8+ |
| Old logs showing | Use `shadow9 service logs -c` |
| Config errors | Check `tor --version` is 0.4.8+ |

## Requirements

- Python 3.10+
- Tor 0.4.8+ (for Conflux)
- Linux/macOS/Windows

## License

MIT
