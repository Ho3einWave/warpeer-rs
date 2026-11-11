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

- Rust 1.80 or newer to build.
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

## Architecture

| Concern | Crate / module |
|---|---|
| WireGuard protocol (Noise) | [`boringtun`] wrapped in `wg::engine` |
| Userspace TCP/IP + DNS | [`smoltcp`] in `netstack` |
| WARP account API | `warp::api` (reqwest + rustls) |
| Obfuscation | `obfs` |
| Mixed proxy | `proxy` |

Data path in normal mode:

```
SOCKS/HTTP client
      │
      ▼
  proxy ──► NetStack (smoltcp, dedicated poll task) ◄──► wg::engine ──UDP──► WARP edge
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
| `--outer-config <FILE>` | custom standard WireGuard outer; WARP remains inner |
| `--inner-config <FILE>` | custom standard WireGuard inner; WARP remains outer |
| `--tun` | full-system TUN mode (Windows; Administrator + `wintun.dll`) |
| `--scan` / `--rtt <ms>` | scan for endpoints / max acceptable RTT |
| `-4` / `-6` | restrict endpoint address family |
| `--tcp-buf <KiB>` | per-direction TCP buffer per connection (default 2048; window for high-RTT links) |
| `--mtu <bytes>` | tunnel MTU for the userspace netstack (default 1330) |
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

## Acknowledgements

- [warp-plus](https://github.com/bepass-org/warp-plus) — the WARP/gool behaviour and
  obfuscation this project ports.
- [boringtun](https://github.com/cloudflare/boringtun) — Cloudflare's Rust WireGuard
  implementation.
- [smoltcp](https://github.com/smoltcp-rs/smoltcp) — the userspace TCP/IP stack.

[`boringtun`]: https://crates.io/crates/boringtun
[`smoltcp`]: https://crates.io/crates/smoltcp
