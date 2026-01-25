# Shadow9 Manager

A secure SOCKS5 proxy server with Tor routing, per-user settings, and DPI bypass.

## Features

- **SOCKS5 Proxy** - RFC 1928/1929 compliant with authentication
- **Per-User Tor Routing** - Each user gets isolated Tor circuits
- **Bridge Support** - obfs4, snowflake, meek to hide Tor usage
- **DPI Bypass** - Multiple security levels for restrictive networks
- **Per-User Ports** - Dedicated listener ports per user

## Quick Start

```bash
# Clone and setup
git clone https://github.com/regix1/shadow9-manager.git
cd shadow9-manager
chmod +x setup shadow9
./setup

# Create a user
./shadow9 user generate

# Start server
./shadow9 serve
```

Connect your application to `127.0.0.1:1080` with your username/password.

## Commands

```bash
# Server
./shadow9 serve                     # Start server
./shadow9 serve --host 0.0.0.0 --port 8080

# Users
./shadow9 user generate             # Create user (interactive)
./shadow9 user generate --username myuser --password "MyP@ss123!"
./shadow9 user list                 # List all users
./shadow9 user info <username>      # Show user details
./shadow9 user modify <username>    # Change settings
./shadow9 user remove <username>    # Delete user

# Service (Linux)
sudo ./shadow9 service install      # Install systemd service
sudo ./shadow9 service start|stop|restart
sudo ./shadow9 service status
sudo ./shadow9 service logs [-f]

# Utilities
./shadow9 check-tor                 # Test Tor connection
./shadow9 setup                     # Install Tor and bridges
```

## User Settings

Create users with custom settings:

```bash
./shadow9 user generate --username myuser --password "MyP@ss123!" \
  --tor --bridge obfs4 --security paranoid --ports "80,443" --rate-limit 100
```

| Option | Flag | Values | Default |
|--------|------|--------|---------|
| Tor Routing | `--tor/--no-tor` | - | `--tor` |
| Bridge | `--bridge` | none, obfs4, snowflake, meek | none |
| Security | `--security` | none, basic, moderate, paranoid | basic |
| Ports | `--ports` | comma-separated or "all" | all |
| Rate Limit | `--rate-limit` | requests/min | unlimited |
| Bind Port | `--bind-port` | dedicated listener port | shared |

### Security Levels

| Level | Description |
|-------|-------------|
| none | Raw SOCKS5, maximum speed |
| basic | TLS wrapping |
| moderate | TLS + packet splitting |
| paranoid | Full DPI bypass |

### Bridge Types

| Bridge | Use Case |
|--------|----------|
| none | Unrestricted networks |
| obfs4 | ISPs blocking Tor |
| snowflake | Heavy censorship |
| meek | Extreme censorship (Azure CDN) |

## Per-User Ports

Users can have dedicated listener ports:

```bash
./shadow9 user generate --username vip --password "MyP@ss123!" --bind-port 8081
```

The server automatically spawns a listener on port 8081 for this user.

## Multi-Bridge Architecture

The server automatically starts separate Tor instances for each bridge type in use:

```
Tor Instances:
  none: 127.0.0.1:9050
  obfs4: 127.0.0.1:9051
  snowflake: 127.0.0.1:9052

Users are routed to their configured bridge automatically.
```

## Configuration

Config file: `config/config.yaml`

```yaml
server:
  host: "0.0.0.0"
  port: 1080

tor:
  socks_host: "127.0.0.1"
  socks_port: 9050
  control_port: 9051

auth:
  credentials_file: "config/credentials.enc"
```

Environment: `SHADOW9_MASTER_KEY` - encryption key for credentials

## Tor Installation

```bash
# Linux
sudo apt install tor && sudo systemctl start tor

# macOS
brew install tor && brew services start tor

# Windows
# Download Tor Expert Bundle from torproject.org
```

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT
