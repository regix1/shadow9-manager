# Shadow9 Manager

Multi-user SOCKS5 proxy that can route each user through Tor, with obfs4 and
Snowflake bridges for networks that block it. It also runs a WireGuard hub so
other machines and routers can reach the proxy over a tunnel.

Proper docs are coming back later. Until then, `--help` on any command is the
current reference:

```
shadow9 --help
shadow9 socks5 --help
shadow9 wg --help
```

## Install

```
git clone https://github.com/regix1/shadow9-manager.git
cd shadow9-manager
chmod +x setup shadow9
./setup
```

On Windows run `setup.bat` instead. Afterwards, `shadow9 setup` installs Tor
and the bridge transports if you want them.

## Run it

```
shadow9 socks5 user generate
shadow9 socks5 serve
```

Point your SOCKS5 client at 127.0.0.1:1080 with the credentials it printed.

The proxy only listens on loopback unless you pass `--host 0.0.0.0`, and if
you do open it up, put a firewall rule in front of it. To keep it running,
`sudo shadow9 socks5 service install` sets it up as a systemd service.
