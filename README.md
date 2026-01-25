# Shadow9 Manager

A secure SOCKS5 proxy server with Tor network support, authentication, and DPI bypass capabilities.

## Features

- **SOCKS5 Proxy Server** - RFC 1928/1929 compliant with username/password authentication
- **Per-User Tor Routing** - Each user gets their own isolated Tor circuit via `IsolateSOCKSAuth`
- **Circuit Isolation** - Users with Tor enabled get unique exit IPs, preventing cross-user tracking
- **DPI Bypass** - Modern techniques to evade Deep Packet Inspection (GoodbyeDPI, ByeDPI inspired)
- **TLS Encryption** - Wrap SOCKS5 in TLS to appear as HTTPS traffic
- **Bridge Support** - Use obfs4, snowflake, or meek bridges to hide Tor usage
- **Secure Authentication** - Argon2id password hashing, encrypted credential storage
- **Per-User Settings** - Each user controls their own connection:
  - **Tor Routing** - Enable/disable Tor per user (anonymous vs fast)
  - **Bridge Type** - obfs4, snowflake, or meek to hide Tor usage
  - **Security Level** - none, basic, moderate, or paranoid DPI evasion
  - **Port Restrictions** - Limit which ports a user can connect to
  - **Rate Limiting** - Control requests per minute per user

## Quick Start

### 1. Clone and Install Python Environment

```bash
git clone https://github.com/regix1/shadow9-manager.git
cd shadow9-manager

# Make scripts executable (Linux/macOS only)
chmod +x setup shadow9

# Run the setup script (creates virtual environment and installs Python dependencies)
./setup
```

### 2. Install Tor and Bridges (Optional)

```bash
# Check what's already installed
./shadow9 setup --check-only

# Install Tor daemon and pluggable transports (obfs4proxy, snowflake)
./shadow9 setup
```

This step is optional if you only want to use the proxy without Tor routing.

### 3. Create a User

```bash
# Generate a user with random credentials
./shadow9 user generate

# Or specify your own username and/or password
./shadow9 user generate --username myuser --password "MySecureP@ss123"

# Interactive mode - prompts for custom or random credentials
./shadow9 user generate
```

### 4. Start the Server

```bash
./shadow9 serve
```

### 5. Connect

Configure your application to use SOCKS5 proxy:
- **Host:** 127.0.0.1
- **Port:** 1080
- **Username:** Your username (e.g., `myuser`)
- **Password:** Your password

Each user has their own credentials and routing settings (Tor/direct, security level, etc.).

## Installation

### Prerequisites

- Python 3.10 or higher
- Tor daemon (optional, for Tor routing)
- pip

### Manual Installation

```bash
# Clone the repository
git clone https://github.com/regix1/shadow9-manager.git
cd shadow9-manager

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate
# On Windows:
.\venv\Scripts\activate

# Install dependencies
pip install -e .
```

## Usage

### Setup Script

Run the setup script for initial configuration:

```bash
./setup
```

This will:
- Create a Python virtual environment
- Install all dependencies
- Generate a master encryption key
- Configure Tor connection settings (if Tor is installed)

### Management Script

Use the management script for ongoing operations:

```bash
# Show help
./shadow9 --help
./shadow9                                            # Also shows help
./shadow9 user                                       # Shows user subcommands

# Start the server
./shadow9 serve

# User management
./shadow9 user generate                              # Generate/create a new user
./shadow9 user remove <username>                     # Remove a user
./shadow9 user list                                  # List all users
./shadow9 user info <username>                       # Show user details
./shadow9 user modify <username>                     # Change user settings
./shadow9 user enable <username>                     # Enable a user
./shadow9 user disable <username>                    # Disable a user

# Server management
./shadow9 stop                                       # Stop the running server

# Tor utilities
./shadow9 check-tor                                  # Check Tor connectivity
./shadow9 fetch <url>                                # Fetch URL through proxy

# System utilities
./shadow9 init                                       # Run initial setup wizard
./shadow9 setup                                      # Install Tor and bridges
./shadow9 status                                     # Check system status
./shadow9 update                                     # Update to latest version
```

### Tab Completion

Tab completion is automatically configured when you run `./setup`. After setup, restart your shell or run:

```bash
source ~/.bashrc   # For Bash
source ~/.zshrc    # For Zsh
```

Then use Tab to auto-complete commands:
```bash
./shadow9 [TAB][TAB]           # Show all commands
./shadow9 user [TAB][TAB]      # Show user subcommands
./shadow9 serve --[TAB][TAB]   # Show serve options
```

### Server Options

The server is minimal - users control their own settings.

```bash
# Start server (listens on all interfaces by default)
./shadow9 serve

# Restrict to localhost only
./shadow9 serve --host 127.0.0.1

# Custom port
./shadow9 serve --port 8080
```

**Note**: Security, bridges, and Tor routing are configured per-user, not at the server level. Each user's settings are applied when they connect.

### User Management

**User-Controlled Architecture**: Each user controls their own connection settings.

| Option | CLI Flag | Description | Default |
|--------|----------|-------------|---------|
| Tor Routing | `--tor/--no-tor` | Route through Tor network | `--tor` |
| Bridge | `--bridge` | Tor bridge (none, obfs4, snowflake, meek) | `none` |
| Security | `--security` | DPI evasion level | `basic` |
| Status | `--enable/--disable` | Enable or disable account | `--enable` |
| Ports | `--ports` | Allowed destination ports | All |
| Rate Limit | `--rate-limit` | Max requests per minute | Server default |

#### Security Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| `none` | Raw SOCKS5, no encryption | Trusted networks, max speed |
| `basic` | TLS wrapping only | Standard protection |
| `moderate` | TLS + packet splitting | Evade basic DPI |
| `paranoid` | Full DPI bypass (SNI frag, desync) | Restrictive networks |

#### Bridge Types (Hide Tor Usage from ISP)

| Bridge | Description | Best For |
|--------|-------------|----------|
| `none` | Direct Tor connection | Unrestricted networks |
| `obfs4` | Obfuscated traffic, looks random | ISPs blocking Tor |
| `snowflake` | Uses WebRTC, looks like video chat | Heavy censorship |
| `meek` | Tunnels through Microsoft Azure CDN | Extreme censorship |

#### Creating Users

```bash
# Generate a user with random credentials (interactive)
./shadow9 user generate
# You'll be prompted for:
#   - Custom or random username
#   - Custom or random password
#   - Tor routing preference

# Generate with specific username
./shadow9 user generate --username myuser

# Generate with specific password
./shadow9 user generate --password "MySecureP@ss123"

# Generate with both custom username and password
./shadow9 user generate --username myuser --password "MySecureP@ss123"

# Generate a user with Tor routing (anonymous)
./shadow9 user generate --username myuser --password "MySecureP@ss123" --tor
# Traffic goes: Client -> Shadow9 -> Tor Network -> Internet

# Generate a user with direct routing (faster, not anonymous)
./shadow9 user generate --username myuser --password "MySecureP@ss123" --no-tor
# Traffic goes: Client -> Shadow9 -> Internet

# Generate a user with paranoid security (for restrictive networks)
./shadow9 user generate --username myuser --password "MySecureP@ss123" --tor --security paranoid

# Generate a user with obfs4 bridge (hide Tor from ISP)
./shadow9 user generate --username myuser --password "MySecureP@ss123" --tor --bridge obfs4

# Generate a user with snowflake bridge (for heavy censorship)
./shadow9 user generate --username myuser --password "MySecureP@ss123" --tor --bridge snowflake --security paranoid

# Generate a user with port restrictions (only HTTP/HTTPS)
./shadow9 user generate --username myuser --password "MySecureP@ss123" --ports "80,443"

# Generate a user with rate limiting
./shadow9 user generate --username myuser --password "MySecureP@ss123" --rate-limit 100

# Combine multiple options
./shadow9 user generate --username secure_user --password "MySecureP@ss123" --tor --security paranoid --ports "80,443,8080" --rate-limit 50

# Generate random credentials with all options
./shadow9 user generate --tor --security moderate

# Generate random credentials with direct routing
./shadow9 user generate --no-tor --security none
```

#### Viewing User Information

```bash
# List all users with their routing settings
./shadow9 user list

# Example output:
#          Configured Users
# +-----------------------+---------+
# | Username              | Routing |
# |-----------------------+---------|
# | alice                 | Tor     |
# | bob                   | Direct  |
# | user_a1b2c3d4e5f6g7h8 | Tor     |
# +-----------------------+---------+

# View detailed info about a specific user
./shadow9 user info alice

# Example output:
#              User: alice
# +--------------------------------------------+
# | Property      | Value                      |
# |---------------+----------------------------|
# | Username      | alice                      |
# | Status        | Enabled                    |
# | Routing       | Tor + obfs4 bridge         |
# | Security      | PARANOID                   |
# | Allowed Ports | 80, 443                    |
# | Rate Limit    | 50 req/min                 |
# | Created       | 2026-01-24T10:30:00.000000 |
# | Last Used     | 2026-01-24T15:45:00.000000 |
# +--------------------------------------------+
```

#### Modifying Users

```bash
# Change a user's Tor routing preference
./shadow9 user modify alice --no-tor    # Switch to direct
./shadow9 user modify alice --tor       # Switch to Tor

# Enable or disable a user account
./shadow9 user modify alice --disable   # Prevent login
./shadow9 user modify alice --enable    # Allow login

# Change security level
./shadow9 user modify alice --security paranoid
./shadow9 user modify alice --security none

# Change bridge type
./shadow9 user modify alice --bridge obfs4
./shadow9 user modify alice --bridge snowflake
./shadow9 user modify alice --bridge none  # Remove bridge

# Restrict which ports a user can connect to
./shadow9 user modify alice --ports "80,443,8080"
./shadow9 user modify alice --ports "all"  # Remove restrictions

# Set rate limiting
./shadow9 user modify alice --rate-limit 100
./shadow9 user modify alice --rate-limit 0   # Use server default

# Modify multiple settings at once
./shadow9 user modify alice --tor --security paranoid --ports "80,443" --rate-limit 50

# Quick enable/disable shortcuts
./shadow9 user enable alice
./shadow9 user disable alice
```

#### Removing Users

```bash
# Remove a user (requires confirmation)
./shadow9 user remove alice

# Force removal without confirmation
./shadow9 user remove alice --yes
```

#### Example: Setting Up Multiple Users

```bash
# Create an anonymous user for sensitive browsing (maximum security)
./shadow9 user generate --username secure_user --password "Str0ngP@ssword!" --tor --bridge obfs4 --security paranoid --ports "443"
# This user: Tor + obfs4 bridge, DPI bypass, HTTPS only

# Create a fast user for regular browsing (minimum overhead)
./shadow9 user generate --username fast_user --password "Str0ngP@ssword!" --no-tor --security none
# This user: direct connection, no encryption overhead, all ports allowed

# Create a balanced user for everyday use
./shadow9 user generate --username daily_user --password "Str0ngP@ssword!" --tor --security basic --rate-limit 200
# This user: Tor routing, TLS wrapping, rate limited

# Create a restricted user for shared access
./shadow9 user generate --username guest_user --password "Str0ngP@ssword!" --no-tor --security basic --ports "80,443" --rate-limit 50
# This user: direct, HTTP/HTTPS only, heavily rate limited

# Generate a temporary high-security user (random credentials)
./shadow9 user generate --tor --security paranoid
# Note the credentials, then disable when not needed:
./shadow9 user disable user_abc123

# View all configured users
./shadow9 user list
```

#### Password Requirements

When creating users, passwords must meet these security requirements:
- Minimum 12 characters
- At least one uppercase letter (A-Z)
- At least one lowercase letter (a-z)
- At least one digit (0-9)
- At least one special character (!@#$%^&*()-_=+)

## Configuration

Configuration file is located at `config/config.yaml`:

```yaml
server:
  host: "0.0.0.0"
  port: 1080
  max_connections: 100

tor:
  socks_host: "127.0.0.1"
  socks_port: 9050
  control_port: 9051

auth:
  require_auth: true
  credentials_file: "config/credentials.enc"

security:
  allowed_ports: [80, 443, 8080, 8443]
```

**Note**: Tor routing is configured per-user, not at the server level. The `tor` section only configures how to connect to the Tor daemon. Each user's `--tor/--no-tor` setting determines whether their traffic is routed through Tor.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SHADOW9_MASTER_KEY` | Master key for encrypting credentials |

## Tor Setup

### Linux

```bash
# Ubuntu/Debian
sudo apt install tor

# Start Tor service
sudo systemctl start tor
```

### macOS

```bash
brew install tor
brew services start tor
```

### Windows

Download Tor Expert Bundle from [torproject.org](https://www.torproject.org/download/tor/)

## Testing Your Connection

```bash
# Check Tor connectivity
./shadow9 check-tor

# Fetch a URL through Tor
./shadow9 fetch https://check.torproject.org

# Fetch an .onion site
./shadow9 fetch http://duckduckgogg42xjoc72x3sjasowadjgfcebqnhel.onion/
```

## Security Considerations

1. **Credentials** - Stored encrypted with Argon2id hashing
2. **Master Key** - Set via environment variable, never stored in files
3. **TLS** - Self-signed certificates generated on startup
4. **Permissions** - Credential files are chmod 600 on Unix
5. **Tor Circuit Isolation** - Each user with Tor enabled gets their own isolated circuit via Tor's `IsolateSOCKSAuth` feature. This means:
   - Different users get different exit IPs
   - Users cannot correlate each other's traffic
   - Compromising one user's session doesn't affect others

## Troubleshooting

### "Tor not detected"

Make sure Tor daemon is running:
```bash
# Linux
sudo systemctl status tor

# Check if SOCKS port is open
ss -tlnp | grep 9050
```

### "Authentication failed"

Password requirements:
- Minimum 12 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character

### "Connection refused"

1. Check if server is running: `./shadow9 status`
2. Verify port is not in use: `netstat -tlnp | grep 1080`
3. Check firewall rules

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Format code
black src/

# Type checking
mypy src/
```

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `pytest tests/ -v`
5. Submit a pull request
