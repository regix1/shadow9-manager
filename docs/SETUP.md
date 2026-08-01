# Setting up a shadow9 WireGuard tunnel

One hub, any number of spokes. A **node** is a machine that joins itself, and with a
route it becomes a site gateway for a whole LAN. A **device** is something that cannot
run shadow9, like a phone, and gets a config file and a QR code.

Everything below is done as the operator. Hub setup tries each root-level host change and
prints the exact command when it cannot make one. Node setup still applies its own config.

---

## Before you start

On the hub:

- shadow9 installed and `shadow9 master-key generate` already run, so the master key exists.
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

Running `shadow9 wg init` without flags asks for the endpoint when it has an interactive
terminal. Before the question, shadow9 checks which local address the host would use to
reach the internet. When that address is publicly routable, the prompt offers it with the
configured WireGuard listen port, says it came from the host's route, and Enter accepts it.
When the detected address is private, shadow9 says peers on the internet cannot dial it and
leaves the prompt empty. A failed check also leaves the prompt unchanged. It never contacts
an outside address service during setup.

A script, redirected command, or test has no terminal to answer that question, so it must
pass `--endpoint`; shadow9 stops before writing a key or config when the flag is missing.

That one value drives two separate things, which is worth knowing before you get it
wrong: it becomes the `Endpoint` line in every peer's config, and its host half becomes
the host of the enrollment URL printed in join commands. A private or wrong address
breaks both at once, and shadow9 warns when the address is not one the internet routes
to rather than refusing it.

Other options worth knowing:

| Option | Why |
|---|---|
| `--interface s9hub` | Use another hub interface name. The default is `wg0`. |
| `--network 10.9.0.0/24` | A different tunnel range. Must be private; a public range is refused. |
| `--port` | A different UDP port. |
| `--masquerade-interface eth0` | Only needed if full-tunnel devices should reach the internet. |
| `--token-hours` | How long the printed join token lasts. Default 24. |
| `--force` | Stop and replace the selected interface and boot config, and replace the hub key. Every peer must rejoin. |
| `--no-apply` | Write the key and config without changing the host or starting the tunnel. |

`shadow9 wg setup` walks the same thing with prompts, including the endpoint suggestion.

`wg init` and `wg setup` write the hub key, render the config, and then try four independent
host changes:

1. Bring the selected interface up with `wg-quick`.
2. Link shadow9's config into `/etc/wireguard` and enable its `wg-quick@` unit for reboot.
3. Turn on IP forwarding and record it in `/etc/sysctl.d/99-shadow9.conf`.
4. Check for the selected interface's tunnel-to-tunnel FORWARD rule and add it only when
   it is absent.

The forwarding key and firewall command follow the tunnel network: IPv4 uses
`net.ipv4.ip_forward` and `iptables`; IPv6 uses `net.ipv6.conf.all.forwarding` and
`ip6tables`. The command finishes with a four-line summary. One failed step does not stop
the other three. The summary keeps the text printed by a failed command, so an error such
as `wg0 already exists` is not flattened into a permission hint.

Before writing a hub key or config, init checks for a live WireGuard interface with the
selected name and for `/etc/wireguard/<name>.conf`. If this host already runs `wg0`, either
choose another name:

```
shadow9 wg init --interface s9hub --endpoint 203.0.113.10:51820
```

Or deliberately replace it:

```
shadow9 wg init --force --endpoint 203.0.113.10:51820
```

The forced path stops the live interface before starting shadow9's replacement. A
conflicting boot config is moved beside itself as `wg0.conf.before-shadow9` (with a numeric
suffix if needed), then replaced by shadow9's link. `shadow9 wg setup` asks for the same
confirmation interactively.

To put the newest preserved config back and restart that interface:

```
shadow9 wg restore
shadow9 wg restore --interface office
```

The configured interface is used when `--interface` is omitted, so the first command restores
`wg0` on a default setup. Use `--backup /etc/wireguard/office.conf.before-shadow9` to select a
specific saved version and `--force` to skip confirmation. Restore only replaces Shadow9's
managed link (or an empty target), keeps that link as `<interface>.conf.shadow9`, and rolls the
filesystem back if the preserved interface cannot start.

The chosen name is saved in `wireguard.interface`. Hub config regeneration, endpoint
changes, device configs, activation, the FORWARD rule and handshake checks keep using it.
On Windows, or when the host cannot report its live WireGuard interfaces, init carries on
with the checks it can make.

## 2. If activation needs manual work

No root access, Windows, a host without systemd, or a missing command are normal outcomes.
`wg init` says what it could not do and prints the command to run. The commands below are
the same fallback in one place.

shadow9 renders the config under its own install root, at
`config/wireguard/<interface>.conf`, which `init` prints. The examples below use the
default `wg0`; replace both the path and interface name when `--interface` selected another
one:

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

If `/etc/wireguard/wg0.conf` already exists, init stops before writing anything unless
`--force` was given. The forced path preserves the old entry before installing shadow9's
link.

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

When the hub has the complete CI package set under `node/packages`, `shadow9 wg init`
prints these commands. They pick the package from the router's own release and hardware;
you do not have to translate an OpenWrt name into a Go name:

```
release="$(. /etc/openwrt_release; echo "$DISTRIB_RELEASE")"
machine="$(uname -m)"
case "$machine" in
  x86_64) architecture=amd64 ;;
  aarch64) architecture=arm64 ;;
  mips*) architecture=mipsle ;;
  *) echo "No shadow9 package matches $machine"; exit 1 ;;
esac
case "$release" in
  24.10.*) package=ipk ;;
  25.12.*) package=apk ;;
  *) echo "No shadow9 package matches OpenWrt $release"; exit 1 ;;
esac
wget -O "/tmp/shadow9-node.$package" \
  "http://203.0.113.10:8081/api/wireguard/node/package/$package/$architecture"
sha256sum "/tmp/shadow9-node.$package"
```

Compare that checksum with the `ipk/<architecture>` or `apk/<architecture>` line on the
hub's own screen before installing. Then run:

```
case "$package" in
  ipk) opkg install /tmp/shadow9-node.ipk ;;
  apk) apk add --allow-untrusted /tmp/shadow9-node.apk ;;
esac
```

The file is downloaded before it is installed. Do not pass its URL to `opkg`: `opkg`
builds a temporary filename from the whole redirected URL, including its long query
string, and can fail at the 255-byte filename limit.

A git clone does not contain CI packages. If the hub says its package set is absent or
incomplete, get the exact router package and `SHA256SUMS` from the
[v0.1.0 release](https://github.com/regix1/shadow9-manager/releases/tag/v0.1.0). The six
release names cover all supported combinations:

```
24.10 x86_64  -> shadow9-node_0.1.0-r1_x86_64.ipk
24.10 aarch64 -> shadow9-node_0.1.0-r1_aarch64_generic.ipk
24.10 mipsel  -> shadow9-node_0.1.0-r1_mipsel_24kc.ipk
25.12 x86_64  -> shadow9-node-0.1.0-r1_x86-64.apk
25.12 aarch64 -> shadow9-node-0.1.0-r1_armsr-armv8.apk
25.12 mipsel  -> shadow9-node-0.1.0-r1_ramips-mt7621.apk
```

Download the selected release file to `/tmp/shadow9-node.ipk` or
`/tmp/shadow9-node.apk`, check it against the release checksum, and use the same install
case above. The CI `node-packages` artifact can also be unpacked as `node/packages` on a
hub; it contains all six files and their `SHA256SUMS`.

The hub prints a raw-binary fallback only when all three raw binaries and checksums are
present. It detects `uname -m` before downloading `linux-$architecture`. That fallback is
for a router with no package: it does not install `wireguard-tools`,
`luci-proto-wireguard`, the boot service, or the conffile that preserves identity across
`sysupgrade`.

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
- **A git clone has no CI packages.** Put the `node-packages` artifact under
  `node/packages`, or use the release link the hub prints.
- **The admin API is plain HTTP with a cleartext key.** The split listener means it
  never has to leave `127.0.0.1`, which is the practical answer, but it is not encrypted.
- **The signed join stops impersonation, not denial of service.** Someone on the network
  path can still stop a join from completing.
