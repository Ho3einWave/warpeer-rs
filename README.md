# warpeer

A userspace Cloudflare WARP client written in Rust — a port of the WARP parts of
[warp-plus](https://github.com/bepass-org/warp-plus) (**without** the Psiphon/cfon
feature). It speaks WireGuard entirely in user space and exposes the tunnel as a
local **mixed proxy** (SOCKS5, SOCKS4/4a and HTTP CONNECT on one port).

It is a single binary with no kernel WireGuard module and no TUN device required
(except for the optional Windows TUN mode): the WireGuard engine, the TCP/IP stack,
DNS, the proxy and the obfuscation all live in the process.

Features:

- **Normal WARP** — a single WireGuard tunnel to a Cloudflare WARP endpoint.
- **MASQUE** — Cloudflare's newer CONNECT-IP over HTTP/3 transport (with
  automatic HTTP/2 fallback when UDP/443 is filtered).
- **MASQUE-in-MASQUE** — an inner MASQUE tunnel carried through an outer MASQUE tunnel.
- **warp-in-warp (gool)** — a second WARP tunnel nested inside the first.
- **Custom outer WireGuard** — run WARP inside a standard WireGuard tunnel.
- **Custom inner WireGuard** — run a standard WireGuard tunnel inside WARP.
- **TUN mode (Windows)** — route ALL system traffic through WARP via a Wintun adapter.
- **Mixed proxy** — SOCKS5, SOCKS4/4a and HTTP CONNECT on the same port, with DNS
  resolved through the tunnel.
- **Endpoint scanner** — find responsive, low-RTT WARP endpoints via real handshakes.
- **Junk-packet obfuscation** — both the warp-plus "trick" (`t1`/`t2`) and
  **AmneziaWG**-style knobs (`Jc`/`Jmin`/`Jmax`/`Jdelay`).
- **Tunable data path** — TCP window (`--tcp-buf`) and tunnel MTU (`--mtu`) for
  high-RTT links.

## Requirements

- Rust 1.95 or newer to build.
- Linux or Windows. TUN mode is Windows-only (Wintun); the proxy and gool modes work
  on Linux.
- TUN mode needs **Administrator** rights and **`wintun.dll`** from
  <https://www.wintun.net> (matching your CPU arch) next to `warpeer.exe`.

## Building

```sh
cargo build --release
# binary: target/release/warpeer (target/release/warpeer.exe on Windows)
```

On Windows, `build.ps1` wraps the native Windows build and a Linux build through
WSL (into a separate `target-linux/` directory):

```powershell
.\build.ps1              # Windows + Linux release binaries
.\build.ps1 -Target linux
.\build.ps1 -Dev         # debug profile
```

## Usage

```sh
# Normal WARP on 127.0.0.1:8086
warpeer

# Pick a specific endpoint
warpeer -e 188.114.97.6:8854

# Scan for a fast endpoint first
warpeer --scan --rtt 1000

# warp-in-warp, scanning for two endpoints
warpeer --gool --scan

# WARP as the inner tunnel, using a standard WireGuard config as the outer
warpeer --outer-config outer.conf --scan -4

# WARP as the outer tunnel, using a standard WireGuard config as the inner
warpeer --inner-config inner.conf --scan -4

# WARP+ license
warpeer -k <LICENSE_KEY>

# MASQUE (CONNECT-IP over HTTP/3, automatic HTTP/2 fallback)
warpeer --masque

# Force HTTP/2 for MASQUE (UDP/443 filtered networks)
warpeer --masque --masque-h2

# Reuse an existing usque-compatible MASQUE config
warpeer --masque --masque-config /path/to/config.json
```

The proxy speaks three protocols on the same port, detected from the first byte:
SOCKS5 (`0x05`), SOCKS4/4a (`0x04`) and HTTP proxy (CONNECT or plain absolute-form
requests). DNS for proxy targets is resolved through the tunnel.

### TUN mode (Windows — full-system VPN)

Routes **all** traffic through WARP via a Wintun adapter (no per-app SOCKS config needed).

```sh
# all traffic via WARP, scanning for a good endpoint
warpeer --tun --scan

# all traffic via warp-in-warp (gool) — system-wide location change
warpeer --tun --gool --scan
```

`--tun --gool` routes the whole system through the *inner* tunnel of a gool chain
(TUN → inner WG → shim → outer WG → Cloudflare), so the opportunistic gool location
change applies to all traffic, not just a SOCKS-configured app.

It auto-configures routing and restores it on exit (Ctrl-C): it pins a host route to the
WARP endpoint via your real gateway (so the encrypted traffic doesn't loop), adds
split-default routes (`0.0.0.0/1` + `128.0.0.0/1`, and `::/1` + `8000::/1`) via the TUN
adapter, and points DNS at the tunnel resolver. In TUN mode there is no proxy.

### MASQUE mode (CONNECT-IP over HTTP/3)

`--masque` uses Cloudflare's MASQUE transport instead of WireGuard. On first run
it registers a separate WARP device with an ECDSA P-256 key, enrolls the key,
and stores a usque-compatible config at `<cache-dir>/masque.json` (mode 0600).
That device is distinct from the WireGuard identity and gets its own assigned
addresses and WARP account.

The client performs mutual TLS against
`consumer-masque.cloudflareclient.com` (pinned to the endpoint key returned by
the API) and opens an RFC 9484 `CONNECT-IP` request. IP packets travel as HTTP/3
datagrams. When UDP/443 is filtered — common on some networks — it falls back to
HTTP/2 (`cf-connect-ip` capsules over TLS/TCP); `--masque-h2` skips the HTTP/3
attempt:

```sh
# automatic: HTTP/3 first, HTTP/2 fallback
warpeer --masque

# force HTTP/2 (skips the HTTP/3 timeout)
warpeer --masque --masque-h2

# reuse a device registered by usque/usque-rs
warpeer --masque --masque-config /path/to/config.json
```

`--masque-config` accepts the `config.json` format used by usque and usque-rs,
so an existing device can be reused without registering a new one. MASQUE
defaults to a 1400-byte tunnel MTU; `--mtu` overrides it.

#### Changing the WARP exit location (NAT64)

Cloudflare normally assigns the nearest WARP exit. You can make the connection
appear to come from another country by connecting through a NAT64 gateway: the
endpoint is the NAT64 IPv6 prefix followed by the WARP IPv4 address encoded in
hex. `--masque-endpoint` sets the MASQUE edge explicitly (WireGuard already
accepts IPv6 via `-e`):

```sh
# NAT64 prefix 2602:fc59:b0:64::, WARP 162.159.198.2 -> a29f:c602
warpeer --masque --masque-endpoint '[2602:fc59:b0:64::a29f:c602]:443'

# WireGuard equivalent (WARP 162.159.199.2 -> a29f:c702, port 2408)
warpeer -e '[2602:fc59:b0:64::a29f:c702]:2408'
```

This is the "Soul Transfer" technique (not a nested tunnel). For a single tunnel
it requires IPv6 on the host; on IPv4-only networks use the MASQUE-in-MASQUE
variant below, where the outer WARP tunnel supplies IPv6. Public NAT64 gateways
have usage limits and extra latency; choose a prefix appropriate for the location
you want and expect variable availability.

#### MASQUE-in-MASQUE

`--masque-gool` registers two separate WARP devices and carries the inner MASQUE
session as TCP through the outer MASQUE tunnel's netstack. Both layers are
MASQUE. The outer can be HTTP/3 or HTTP/2; the inner is HTTP/2, so the chain
works even when UDP/443 is filtered. The proxy is served on the inner tunnel.

```sh
# outer HTTP/2 (skip the HTTP/3 probe) + inner HTTP/2
warpeer --masque-gool --masque-h2
```

The two devices are auto-registered and stored as `masque-gool-outer.json` and
`masque-gool-inner.json` in the cache directory. Existing devices can be
supplied with `--masque-config` (outer) and `--masque-inner-config` (inner);
they must be different WARP devices.

**Changing the location through the chain.** Plain nesting keeps the outer
exit (`loc=IR`, `colo=FRA` on the test line for WireGuard, single MASQUE and
MASQUE-in-MASQUE). To change the country, point the **inner** endpoint at a
NAT64-synthesized IPv6 address. The outer MASQUE tunnel supplies IPv6 even on an
IPv4-only host, so this works without IPv6 on the local network:

```sh
# US (Chicago) NAT64 prefix, inner MASQUE edge 162.159.198.2 -> a29f:c602
warpeer --masque-gool --masque-h2 \
  --masque-inner-endpoint '[2602:fc59:11:64::a29f:c602]:443'
```

Measured on the test line:

| Path | IP | Colo | Location |
|---|---|---|---|
| WireGuard | 104.28.214.164 | FRA | **IR** |
| single MASQUE | 104.28.246.167 | FRA | **IR** |
| MASQUE-in-MASQUE + US NAT64 | 104.28.235.119 | **ORD** | **US** |

Throughput through that public NAT64 gateway was ~0.2–1.2 MB/s and varies; use
this path for location, not for speed. The US Fremont prefix
(`2602:fc59:b0:64::a29f:c602`) also worked once (SJC/US) but was flaky; the
Netherlands, Germany and Finland prefixes failed at test time. Public gateways
are shared and availability changes. Other known prefixes include
`2a02:898:146:64::a29f:c602` (NL), `2001:67c:2960:6464::a29f:c602` (DE) and
`2001:67c:2b0:db32:0:1:a29f:c602` (FI). Use them responsibly.

MASQUE (including `--masque-gool`) currently cannot be combined with `--gool`,
`--tun`, `--scan` or `-e`.
HTTP/2 fallback is reliable but slower than HTTP/3 (and slower than WireGuard
on a healthy path).

### Obfuscation

By default warpeer tries the warp-plus trick `t1` then `t2`. To use AmneziaWG-style
junk instead:

```sh
# Jc=8 packets, Jmin=50, Jmax=200 bytes, Jdelay=15ms between packets
warpeer --jc 8 --jmin 50 --jmax 200 --jdelay 15

# Disable obfuscation entirely
warpeer --no-obfs
```

Junk is emitted before each proactively-sent handshake. Keepalive junk is sent
concurrently so a burst never stalls forwarded traffic.

### Tuning for speed

The userspace TCP stack's socket buffer sets the advertised receive window. On a
high-RTT path the default 256 KiB window would cap throughput, so `--tcp-buf`
defaults to **2048 KiB (2 MiB) per direction** (4 MiB of RAM per active connection):

```sh
# faster on high-RTT/lossless links, more memory
warpeer --tcp-buf 2048

# memory-constrained device
warpeer --tcp-buf 512

# smaller/larger tunnel MTU (default 1330)
warpeer --mtu 1420
```

Bigger is not always better: on a lossy path an oversized window amplifies loss
recovery. The default 2 MiB is a good balance; 4 MiB measured worse on a lossy
test path.

Handshake RTT is a poor predictor of throughput — an endpoint that answers a
handshake in 90 ms can still deliver under 2 MB/s under load. Validate candidates
with a real transfer before pinning one in your service config.

MASQUE over HTTP/2 measured ~4.6–5.5 MB/s with `--mtu 1400` on a network where
UDP/443 was filtered, while WireGuard with the 2 MiB buffer reached ~12–13 MB/s
on the same 120 Mbps line. HTTP/3 (where UDP works) is the faster MASQUE path;
the HTTP/2 fallback is for networks that cannot use it.

## Architecture

| Concern | Crate / module |
|---|---|
| WireGuard protocol (Noise) | [`boringtun`] wrapped in `wg::engine` |
| Userspace TCP/IP + DNS | [`smoltcp`] in `netstack` |
| WARP account API | `warp::api` (reqwest + rustls) |
| MASQUE transport | `masque` + vendored `usque-masque` (quinn, h3, h2) |
| Obfuscation | `obfs` |
| Mixed proxy | `proxy` |

Data path in normal mode:

```
SOCKS/HTTP client
      │
      ▼
  proxy ──► NetStack (smoltcp, dedicated poll task) ◄──► wg::engine ──UDP──► WARP edge
```

MASQUE mode replaces the WireGuard engine with the CONNECT-IP transport:

```
proxy ──► NetStack ──► CONNECT-IP (H3 datagrams / H2 capsules) ──TLS──► Cloudflare MASQUE edge
```

The engine owns the UDP socket, so it adds the two WARP-specific behaviours on top
of stock WireGuard:

1. **Reserved bytes.** WARP carries the device's 3-byte `client_id` in WireGuard
   header bytes `1..4`. The engine stamps them onto every outgoing packet and
   **zeroes them on every incoming packet** (boringtun reads bytes `0..4` as the
   message type, so a non-zero reserved field would be rejected).
2. **Junk burst.** Before each proactively-sent handshake the engine emits a burst
   of junk UDP datagrams (see Obfuscation below).

### How warp-in-warp (gool) works

The v2 design avoids a second userspace IP stack. Inner WireGuard datagrams are
hand-wrapped in a UDP/IPv4 frame and fed straight into the outer engine's
encapsulation channel:

```
SOCKS client → [inner WG + netstack] → localhost UDP shim → [outer WG] → Cloudflare
```

1. The **outer** tunnel (primary identity, junk on, IPv4 endpoint) connects to a
   WARP edge.
2. A **shim** listens on `127.0.0.1:0`. Each datagram it receives is wrapped as
   UDP/IPv4 (src = outer interface IP, dst = the WARP endpoint, UDP checksum 0) and
   pushed into the outer engine; decapsulated replies are unwrapped back to the
   shim.
3. The **inner** tunnel (secondary identity, junk **off**, MTU 1280) points its
   peer endpoint at the shim, so inner WireGuard packets travel as the encrypted
   payload of the outer tunnel.
4. The proxy is served on the inner tunnel.

## Key flags

| Flag | Meaning |
|---|---|
| `-b, --bind` | proxy bind address (default `127.0.0.1:8086`) |
| `-e, --endpoint` | WARP endpoint `ip:port` (random if omitted) |
| `-k, --key` | WARP+ license key |
| `--dns` | resolver used inside the tunnel (default `1.1.1.1`) |
| `--gool` | warp-in-warp mode |
| `--masque` | use MASQUE (CONNECT-IP over HTTP/3) instead of WireGuard |
| `--masque-h2` | force HTTP/2 for MASQUE (otherwise HTTP/3 then fallback) |
| `--masque-endpoint <IP[:PORT]>` | override the MASQUE edge (NAT64/IPv6 address; port defaults to 443) |
| `--masque-gool` | MASQUE-in-MASQUE: carry an inner MASQUE tunnel through an outer one (alias `--masque-in-masque`) |
| `--masque-inner-endpoint <IP[:PORT]>` | inner MASQUE edge override for `--masque-gool` (NAT64 for location change) |
| `--masque-inner-config <FILE>` | inner MASQUE config for `--masque-gool`; implies it |
| `--masque-config <FILE>` | reuse a usque-compatible MASQUE config; outer config in `--masque-gool` |
| `--outer-config <FILE>` | custom standard WireGuard outer; WARP remains inner |
| `--inner-config <FILE>` | custom standard WireGuard inner; WARP remains outer |
| `--tun` | full-system TUN mode (Windows; Administrator + `wintun.dll`) |
| `--scan` / `--rtt <ms>` | scan for endpoints / max acceptable RTT |
| `-4` / `-6` | restrict endpoint address family |
| `--tcp-buf <KiB>` | per-direction TCP buffer per connection (default 2048; window for high-RTT links) |
| `--mtu <bytes>` | tunnel MTU (default 1330 WireGuard, 1400 MASQUE) |
| `--cache-dir <DIR>` | directory for the WARP identity (default: OS cache dir) |
| `--jc/--jmin/--jmax/--jdelay` | AmneziaWG junk knobs |
| `--no-obfs` | disable junk obfuscation |
| `--reserved` | override reserved value (`a,b,c` or `random`) |
| `-v, --verbose` | debug logging |

## Project layout

```
src/
  main.rs        CLI, endpoint selection, obfuscation presets
  app.rs         identity -> tunnel + netstack wiring, MTU/buffer tuning
  gool.rs        warp-in-warp shim and nested tunnels
  tunmode.rs     Windows Wintun mode, routing setup/teardown
  masque/        MASQUE mode: registration, TLS/mTLS, CONNECT-IP pump
  obfs.rs        warp-plus trick + AmneziaWG junk bursts
  wgconfig.rs    minimal wg-quick config parser
  wg/            boringtun engine (reserved bytes, junk, timers)
  netstack/      smoltcp interface, channel device, TCP/DNS API
  proxy/         mixed HTTP/SOCKS4/5 proxy and bidirectional pump
  scanner/       concurrent handshake-based endpoint scanner
  warp/          account API, identity persistence, key helpers, endpoints
```

## Notes / limitations

- The scanner ranks endpoints by handshake RTT; use a real transfer to validate
  sustained throughput.
- DNS-through-the-tunnel currently resolves A (IPv4) records only.
- TLS to the registration API uses standard rustls (no uTLS ClientHello camouflage yet).
- The plain-HTTP proxy path rebuilds the first request only; subsequent keep-alive
  requests are forwarded verbatim.
- TUN mode is Windows-only; `--tun` on other platforms fails at startup.
- MASQUE registers a separate WARP device/account on first use; the config contains
  its private key (written `0600`). A `-k` license is applied best-effort.
- MASQUE currently supports the proxy path only (no gool, TUN or endpoint scanning).
- HTTP/3 needs UDP/443; when that is filtered the client falls back to HTTP/2, which
  is reliable but slower.

## Acknowledgements

- [warp-plus](https://github.com/bepass-org/warp-plus) — the WARP/gool behaviour and
  obfuscation this project ports.
- [usque](https://github.com/Diniboy1123/usque) and
  [usque-rs](https://github.com/FireMasterK/usque-rs) — the open-source Cloudflare
  MASQUE implementations this mode is based on. `vendor/usque-masque` is a modified
  MIT-licensed copy of the latter (HTTP/2 flow-control fixes); see
  [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
- [boringtun](https://github.com/cloudflare/boringtun) — Cloudflare's Rust WireGuard
  implementation.
- [smoltcp](https://github.com/smoltcp-rs/smoltcp) — the userspace TCP/IP stack.
- A patched [h3](https://github.com/hyperium/h3) lives in `vendor/h3` to accept
  Cloudflare's non-standard `cf-connect-ip` protocol token.

[`boringtun`]: https://crates.io/crates/boringtun
[`smoltcp`]: https://crates.io/crates/smoltcp
