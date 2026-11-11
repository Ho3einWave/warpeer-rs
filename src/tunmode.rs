//! TUN mode (Windows / Wintun): route ALL system traffic through WARP transparently.
//!
//! In TUN mode the OS provides the IP stack, so there's no smoltcp netstack and no
//! SOCKS proxy — we just bridge the TUN device straight to the WARP engine:
//!   TUN read  → encapsulate → WARP
//!   WARP recv → decapsulate → TUN write
//!
//! Requirements: run as Administrator, with `wintun.dll` next to the executable.
//!
//! Routing (auto-configured, restored on exit):
//!   * pin a /32 host route for the WARP endpoint via the real gateway (so the
//!     encrypted WireGuard UDP doesn't loop back into the tunnel),
//!   * add split-default routes (0.0.0.0/1 + 128.0.0.0/1, and ::/1 + 8000::/1) via the
//!     TUN adapter so everything else goes through WARP without deleting the OS default,
//!   * point DNS at the tunnel resolver.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use tracing::{info, warn};

use crate::app::{self, Options, DOUBLE_MTU, SINGLE_MTU};
use crate::warp::Identity;
use crate::wg::Tunnel;

const TUN_NAME: &str = "warpeer";

pub async fn run(opts: &Options, ident: Identity, endpoints: Vec<SocketAddr>) -> Result<()> {
    let endpoint = endpoints[0];

    // Bring up the engine the TUN will bridge to. For gool this is the INNER tunnel
    // (sitting on top of the outer + shim); the TUN takes the inner identity's IP.
    let (outbound_tx, mut inbound_rx, tun_v4, tun_v6, mtu, endpoint_ip, _guards) = if opts.gool {
        let (shim_addr, outer_tunnel, endpoint_ip) =
            crate::gool::setup_outer_and_shim(opts, &ident, &endpoints).await?;

        if let Some(path) = &opts.inner_config {
            let config = crate::wgconfig::load(path).await?;
            let v4 = config.address;
            info!(endpoint = %config.endpoint, "gool+tun: bringing up custom inner tunnel");
            let (inner_tunnel, outbound_tx, inbound_rx) =
                crate::gool::start_custom_engine(config, Some(shim_addr), "inner").await?;
            (
                outbound_tx,
                inbound_rx,
                v4,
                None,
                DOUBLE_MTU,
                endpoint_ip,
                vec![outer_tunnel, inner_tunnel],
            )
        } else {
            let inner = if opts.outer_config.is_some() {
                ident
            } else {
                crate::warp::load_or_create_identity(
                    &opts.cache_dir.join("secondary"),
                    &opts.license,
                )
                .await
                .context("loading secondary identity")?
            };
            let reserved_inner = opts
                .reserved
                .unwrap_or_else(|| inner.reserved().unwrap_or([0, 0, 0]));
            let (v4, v6) = interface_v4_v6(&inner)?;

            info!("gool+tun: bringing up inner tunnel");
            // No junk on the inner tunnel: it is already encrypted by the outer one.
            let inner_attempts = vec![crate::obfs::JunkConfig::disabled()];
            let (inner_tunnel, outbound_tx, inbound_rx) =
                app::start_engine(&inner, shim_addr, reserved_inner, &inner_attempts, 20).await?;

            (
                outbound_tx,
                inbound_rx,
                v4,
                v6,
                DOUBLE_MTU,
                endpoint_ip,
                vec![outer_tunnel, inner_tunnel],
            )
        }
    } else {
        let endpoint_ip = match endpoint {
            SocketAddr::V4(v4) => *v4.ip(),
            SocketAddr::V6(_) => {
                return Err(anyhow!(
                    "tun mode currently requires an IPv4 endpoint; use -e <ipv4:port> or --scan -4"
                ))
            }
        };
        let reserved = opts.reserved_for(&ident);
        let (v4, v6) = interface_v4_v6(&ident)?;
        let (tunnel, outbound_tx, inbound_rx) =
            app::start_engine(&ident, endpoint, reserved, &opts.obfs_attempts, 5).await?;
        (
            outbound_tx,
            inbound_rx,
            v4,
            v6,
            SINGLE_MTU,
            endpoint_ip,
            vec![tunnel],
        )
    };
    let _guards: Vec<Tunnel> = _guards;

    // Create the Wintun adapter and assign the (inner, for gool) WARP IPv4 address.
    let mut config = tun::configure();
    config
        .tun_name(TUN_NAME)
        .address(tun_v4)
        .netmask(Ipv4Addr::new(255, 255, 255, 255))
        .mtu(mtu as u16)
        .up();
    let dev = tun::create_as_async(&config).context(
        "creating TUN adapter (need Administrator privileges and wintun.dll next to the exe)",
    )?;

    // Configure routing for a full VPN. The guard restores it on drop.
    let _routing = Routing::setup(endpoint_ip, tun_v6, opts.dns)?;

    info!(
        adapter = TUN_NAME,
        gool = opts.gool,
        "tun mode up — all traffic now routes through WARP"
    );

    // 4. Bridge TUN <-> engine in this task so that returning (e.g. on Ctrl-C) drops the
    //    device and routing guard, cleaning everything up.
    let mut rbuf = vec![0u8; SINGLE_MTU + 80];
    loop {
        tokio::select! {
            r = dev.recv(&mut rbuf) => match r {
                Ok(n) if n > 0 => {
                    let _ = outbound_tx.send(rbuf[..n].to_vec());
                }
                Ok(_) => {}
                Err(e) => warn!("tun recv error: {e}"),
            },
            pkt = inbound_rx.recv() => match pkt {
                Some(p) => {
                    if let Err(e) = dev.send(&p).await {
                        warn!("tun send error: {e}");
                    }
                }
                None => break, // engine gone
            },
            _ = tokio::signal::ctrl_c() => {
                info!("ctrl-c: shutting down tun mode");
                break;
            }
        }
    }

    Ok(())
}

/// Extract the IPv4 (required) and optional IPv6 interface address from an identity.
fn interface_v4_v6(ident: &Identity) -> Result<(Ipv4Addr, Option<Ipv6Addr>)> {
    let addrs = app::interface_addresses(ident)?;
    let v4 = addrs
        .iter()
        .find_map(|a| match a {
            IpAddr::V4(x) => Some(*x),
            _ => None,
        })
        .ok_or_else(|| anyhow!("identity has no IPv4 interface address"))?;
    let v6 = addrs.iter().find_map(|a| match a {
        IpAddr::V6(x) => Some(*x),
        _ => None,
    });
    Ok((v4, v6))
}

/// Holds the routing state so it can be torn down on drop.
struct Routing {
    endpoint: Ipv4Addr,
}

impl Routing {
    fn setup(endpoint: Ipv4Addr, v6: Option<Ipv6Addr>, dns: IpAddr) -> Result<Routing> {
        // Find the current physical default gateway (before we add our own default).
        let gateway =
            default_ipv4_gateway().context("could not determine the current default gateway")?;
        info!(%gateway, "pinning WARP endpoint route via physical gateway");

        // Pin the endpoint so the encrypted WG traffic escapes via the physical link.
        run_cmd(
            "route",
            &[
                "add",
                &endpoint.to_string(),
                "mask",
                "255.255.255.255",
                &gateway.to_string(),
                "metric",
                "1",
            ],
        );

        // The Wintun adapter takes a moment to appear; find its interface index.
        let if_index = tun_if_index(TUN_NAME)?;
        info!(if_index, "configuring routes via TUN adapter");

        // Split-default IPv4 routes via the TUN (override the default without deleting it).
        netsh(&[
            "interface",
            "ipv4",
            "add",
            "route",
            "prefix=0.0.0.0/1",
            &format!("interface={if_index}"),
            "nexthop=0.0.0.0",
            "store=active",
        ]);
        netsh(&[
            "interface",
            "ipv4",
            "add",
            "route",
            "prefix=128.0.0.0/1",
            &format!("interface={if_index}"),
            "nexthop=0.0.0.0",
            "store=active",
        ]);

        // DNS through the tunnel.
        netsh(&[
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            &format!("name={TUN_NAME}"),
            "static",
            &dns.to_string(),
            "primary",
        ]);

        // IPv6: assign the address and split-default routes so v6 doesn't leak.
        if let Some(v6) = v6 {
            netsh(&[
                "interface",
                "ipv6",
                "add",
                "address",
                &format!("interface={if_index}"),
                &format!("address={v6}"),
            ]);
            netsh(&[
                "interface",
                "ipv6",
                "add",
                "route",
                "prefix=::/1",
                &format!("interface={if_index}"),
                "store=active",
            ]);
            netsh(&[
                "interface",
                "ipv6",
                "add",
                "route",
                "prefix=8000::/1",
                &format!("interface={if_index}"),
                "store=active",
            ]);
        }

        Ok(Routing { endpoint })
    }
}

impl Drop for Routing {
    fn drop(&mut self) {
        // The TUN's own routes/DNS/v6 address vanish when the adapter is removed (on
        // device drop); we only need to remove the endpoint host route we added to the
        // physical interface.
        info!("restoring routing (removing endpoint route)");
        run_cmd("route", &["delete", &self.endpoint.to_string()]);
    }
}

/// Query the current IPv4 default-route gateway via PowerShell.
fn default_ipv4_gateway() -> Result<Ipv4Addr> {
    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | \
             Sort-Object RouteMetric,ifMetric | Select-Object -First 1).NextHop",
        ])
        .output()
        .context("running powershell to find default gateway")?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    s.parse::<Ipv4Addr>()
        .map_err(|_| anyhow!("could not parse default gateway from '{s}'"))
}

/// Find the interface index of the TUN adapter, retrying while it registers.
fn tun_if_index(name: &str) -> Result<u32> {
    for _ in 0..20 {
        let out = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!("(Get-NetAdapter -Name '{name}' -ErrorAction SilentlyContinue).ifIndex"),
            ])
            .output();
        if let Ok(out) = out {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if let Ok(idx) = s.parse::<u32>() {
                return Ok(idx);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    Err(anyhow!("TUN adapter '{name}' did not appear"))
}

fn run_cmd(program: &str, args: &[&str]) {
    match Command::new(program).args(args).output() {
        Ok(out) if !out.status.success() => {
            let err = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            warn!(
                "`{program} {}` failed: {}",
                args.join(" "),
                if err.trim().is_empty() {
                    stdout.trim()
                } else {
                    err.trim()
                }
            );
        }
        Err(e) => warn!("failed to run `{program}`: {e}"),
        _ => {}
    }
}

fn netsh(args: &[&str]) {
    run_cmd("netsh", args);
}
