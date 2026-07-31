# Setting up a shadow9 WireGuard tunnel

One hub, any number of spokes. A **node** is a machine that joins itself, and with a
route it becomes a site gateway for a whole LAN. A **device** is something that cannot
run shadow9, like a phone, and gets a config file and a QR code.

Everything below is done as the operator. Hub setup tries each root-level host change and
prints the exact command when it cannot make one. Node setup still applies its own config.

---

## Before you start

On the hub:

- shadow9 installed and `shadow9 init` already run, so the master key exists.
- `wireguard-tools`, for `wg-quick`. shadow9 generates keys itself and never shells out
  to `wg`, but the kernel still needs something to bring the interface up.
- A public address. A cloud VM's elastic IP is fine even though the machine cannot see
  it on its own interface.

On a router that will be a site gateway:

- OpenWrt 24.10 or later, with `wireguard-tools` and `luci-proto-wireguard`. Both are
  pulled in by the package.

---

## 1. Create the hub

```
shadow9 wg init --endpoint 203.0.113.10:51820
```

`--endpoint` is `host:port` that peers dial. **The port is the UDP WireGuard port, not
the API port.** A DNS name works as well as an address.

That one value drives two separate things, which is worth knowing before you get it
wrong: it becomes the `Endpoint` line in every peer's config, and its host half becomes
the host of the enrollment URL printed in join commands. A private or wrong address
breaks both at once, and shadow9 warns when the address is not one the internet routes
to rather than refusing it.

Other options worth knowing:

| Option | Why |
|---|---|
| `--network 10.9.0.0/24` | A different tunnel range. Must be private; a public range is refused. |
| `--port` | A different UDP port. |
| `--masquerade-interface eth0` | Only needed if full-tunnel devices should reach the internet. |
| `--token-hours` | How long the printed join token lasts. Default 24. |
| `--no-apply` | Write the key and config without changing the host or starting the tunnel. |

`shadow9 wg setup` walks the same thing with prompts.

`wg init` and `wg setup` write the hub key, render the config, and then try four independent
host changes:

1. Bring `wg0` up with `wg-quick`.
2. Link shadow9's config into `/etc/wireguard` and enable `wg-quick@wg0` for reboot.
3. Turn on IP forwarding and record it in `/etc/sysctl.d/99-shadow9.conf`.
4. Check for the `wg0`-to-`wg0` FORWARD rule and add it only when it is absent.

The forwarding key and firewall command follow the tunnel network: IPv4 uses
`net.ipv4.ip_forward` and `iptables`; IPv6 uses `net.ipv6.conf.all.forwarding` and
`ip6tables`. The command finishes with a four-line summary. One failed step does not stop
the other three.

## 2. If activation needs manual work

No root access, Windows, a host without systemd, or a missing command are normal outcomes.
`wg init` says what it could not do and prints the command to run. The commands below are
the same fallback in one place.

shadow9 renders the config under its own install root, at
`config/wireguard/wg0.conf`, which `init` prints. Replace the example path below with that
printed path:

```
sudo wg-quick up /opt/shadow9/config/wireguard/wg0.conf     # the path init printed
```

To have it start at boot, link it where `wg-quick@.service` looks. The link keeps a
regenerated shadow9 config in step with the file the service reads:

```
sudo mkdir -p /etc/wireguard
sudo ln -s /opt/shadow9/config/wireguard/wg0.conf /etc/wireguard/wg0.conf
sudo systemctl enable wg-quick@wg0
```

If `/etc/wireguard/wg0.conf` already exists, shadow9 leaves it alone. Inspect that file
before moving or removing it. You can still start shadow9's config by its full path with
the `wg-quick up` command above.

`wg-quick` reads the file when the interface comes up, so after a change that rewrites
the hub config, restart it:

```
sudo systemctl restart wg-quick@wg0
```

For traffic to pass **between** two spokes, the hub has to forward it:

```
sudo sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-shadow9.conf
sudo iptables -C FORWARD -i wg0 -o wg0 -j ACCEPT || \
  sudo iptables -A FORWARD -i wg0 -o wg0 -j ACCEPT
```

Both are needed. Either one missing and the tunnels come up while spoke-to-spoke
traffic silently goes nowhere. For an IPv6 tunnel, use
`net.ipv6.conf.all.forwarding=1` and `ip6tables` instead.

## 3. Open two ports

- **UDP 51820** for the tunnel.
- **TCP 8081** for enrollment, refresh and node downloads.
- **Leave TCP 8080 closed.** That is the admin API and it stays on `127.0.0.1`.

Host firewall and cloud security group both.

## 4. Add a phone

```
shadow9 wg device add phone
shadow9 wg device add laptop --full-tunnel
```

The hub generates the device's keypair here, because the QR code has to carry the
private key. This is the opposite of a node join, where the machine makes its own key
and the hub never sees the private half.

Split tunnel is the default: the phone reaches the tunnel and any LAN a gateway
advertises, not everything. `--obfuscate` adds AmneziaWG junk packets and needs an
AmneziaWG client.

Scan the QR. Keep the config file. The hub also stores the key, so it can rebuild the
config when the topology changes, but **the phone has to scan the new QR** for a change
to take effect.

## 5. Add a router as a site gateway

Install the package, matching your release and architecture:

```
opkg install ./shadow9-node_0.1.0-r1_x86_64.ipk                  # 24.10.x
apk add --allow-untrusted ./shadow9-node-0.1.0-r1_x86-64.apk     # 25.12.x
```

Then join, using the token the hub printed:

```
shadow9-node join -hub http://203.0.113.10:8081 \
  -token <token> -advertise 192.168.1.0/24
```

`-advertise` is what makes it a gateway for that LAN rather than just another endpoint.
Use `-token-file /etc/shadow9.token` instead of `-token` to keep it out of shell
history; the package ships that file as a conffile so it survives `sysupgrade`.

The router generates its own keypair and the hub never sees the private half. The
tunnel then appears in LuCI under Network then Interfaces as a real WireGuard interface
with handshake time and transfer counters.

Each token is good for one join. Get another with `shadow9 wg token`.

**Do the first join from a console, not over SSH through the link you are
reconfiguring.** There is a timed revert that puts the previous configuration back if
the tunnel does not come up, and it has not been exercised on real hardware.

## 6. Joining a Linux machine that runs shadow9

```
shadow9 wg join --url http://203.0.113.10:8081 --token <token> --route 192.168.5.0/24
```

Unlike the hub, this one applies its own configuration and runs `wg-quick` for you.
`--no-apply` writes the file and stops.

---

## Living with it

| Command | What it does |
|---|---|
| `shadow9 wg list` | Peers with role, address, advertised subnets, last handshake |
| `shadow9 wg token` | Another single-use join token |
| `shadow9 wg remove <name>` | Removes the peer and reissues every config it appeared in |
| `shadow9 wg hub set-endpoint <addr>` | Changes the address peers dial and bumps the topology revision |
| `shadow9-node refresh` | On a router: pulls current routes, endpoint, MTU and keepalive |

Nodes are pull-based. The hub never held their private keys, so it cannot push them a
new config. A changed hub endpoint, or a second gateway's LAN, reaches a node on its
next `refresh` or its next boot, because the boot service runs `refresh`. Run it by hand
when you do not want to wait.

Hub-held configs, meaning devices, are reissued immediately on any topology change.

---

## Known limits

- **Nothing here has run on real OpenWrt hardware.** The UCI write, commit, reload and
  revert paths are tested against a fake `uci`.
- **The hub does not serve packages yet.** Copy the `.ipk` or `.apk` to the router
  yourself. The printed instructions still describe fetching the raw binary.
- **The admin API is plain HTTP with a cleartext key.** The split listener means it
  never has to leave `127.0.0.1`, which is the practical answer, but it is not encrypted.
- **The signed join stops impersonation, not denial of service.** Someone on the network
  path can still stop a join from completing.
