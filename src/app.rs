//! Application wiring: turn a WARP identity into a running tunnel + SOCKS proxy.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tracing::{info, warn};

use tokio::sync::mpsc;

use crate::netstack::{EngineIo, NetStack};
use crate::obfs::JunkConfig;
use crate::proxy;
use crate::scanner::{self, ScanOptions};
use crate::warp::{self, key, Identity};
use crate::wg::{Tunnel, WgConfig};

/// Channels for driving a WARP engine that has no smoltcp netstack: feed IP packets
/// to encapsulate via the sender, receive decapsulated IP packets via the receiver.
pub(crate) type EngineChannels = (
    Tunnel,
    mpsc::UnboundedSender<Vec<u8>>,
    mpsc::UnboundedReceiver<Vec<u8>>,
);

/// Single-tunnel MTU (matches warp-plus `singleMTU`).
pub const SINGLE_MTU: usize = 1330;
/// warp-in-warp inner-tunnel MTU (matches warp-plus `doubleMTU`).
pub const DOUBLE_MTU: usize = 1280;

pub struct Options {
    pub bind: SocketAddr,
    pub license: String,
    pub dns: IpAddr,
    pub cache_dir: PathBuf,
    /// Explicit reserved override; falls back to the identity's client_id.
    pub reserved: Option<[u8; 3]>,
    /// Obfuscation configs to try in order (e.g. [t1, t2], or one Amnezia config).
    pub obfs_attempts: Vec<JunkConfig>,
    /// warp-in-warp (gool) mode.
    pub gool: bool,
    /// Standard WireGuard config used for the outer tunnel. The inner remains WARP.
    pub outer_config: Option<PathBuf>,
    /// Standard WireGuard config used for the inner tunnel. The outer remains WARP.
    pub inner_config: Option<PathBuf>,
    /// TUN mode: route all system traffic through WARP (Windows, needs Admin).
    pub tun: bool,
    /// MASQUE mode (CONNECT-IP over HTTP/3) instead of WireGuard.
    pub masque: bool,
    /// Existing usque-compatible MASQUE config file.
    pub masque_config: Option<PathBuf>,
    /// Force HTTP/2 for MASQUE (otherwise HTTP/3 then fallback).
    pub masque_h2: bool,
    /// Endpoint address families allowed for MASQUE endpoint selection.
    pub use_v4: bool,
    pub use_v6: bool,
    /// Per-direction TCP socket buffer for tunnel connections (bytes).
    pub tcp_buf: usize,
    /// MTU for the WARP netstack's tunnel interface.
    pub mtu: usize,
    /// Endpoints to use when scanning is disabled (gool needs two; warp uses the first).
    pub endpoints: Vec<SocketAddr>,
    /// When set, scan for endpoints instead of using `endpoints`.
    pub scan: Option<ScanOptions>,
}

impl Options {
    pub fn reserved_for(&self, ident: &Identity) -> [u8; 3] {
        self.reserved
            .unwrap_or_else(|| ident.reserved().unwrap_or([0, 0, 0]))
    }
}

/// Per-tunnel tuning knobs shared by the plain WARP and gool paths.
#[derive(Clone, Copy)]
pub(crate) struct Tuning {
    /// MTU of the tunnel netstack.
    pub mtu: usize,
    /// Persistent keepalive interval in seconds.
    pub keepalive: u16,
    /// Per-direction TCP socket buffer (bytes).
    pub tcp_buf: usize,
}

pub async fn run(mut opts: Options) -> Result<()> {
    if opts.masque {
        return crate::masque::run(&opts).await;
    }

    if opts.outer_config.is_some() || opts.inner_config.is_some() {
        opts.gool = true;
    }

    let primary = warp::load_or_create_identity(&opts.cache_dir.join("primary"), &opts.license)
        .await
        .context("loading primary identity")?;

    let endpoints = match opts.scan.take() {
        Some(scan) => scanner::find_endpoints(&primary, scan).await?,
        None => opts.endpoints.clone(),
    };
    if endpoints.is_empty() {
        return Err(anyhow!("no warp endpoints available"));
    }
    info!(?endpoints, "using warp endpoints");

    if opts.tun {
        crate::tunmode::run(&opts, primary, endpoints).await
    } else if opts.gool {
        crate::gool::run(&opts, primary, endpoints).await
    } else {
        run_warp(&opts, primary, endpoints).await
    }
}

async fn run_warp(opts: &Options, ident: Identity, endpoints: Vec<SocketAddr>) -> Result<()> {
    let reserved = opts.reserved_for(&ident);
    let (netstack, _tunnel) = bring_up(
        &ident,
        endpoints[0],
        reserved,
        &opts.obfs_attempts,
        opts.dns,
        Tuning {
            mtu: opts.mtu,
            keepalive: 5,
            tcp_buf: opts.tcp_buf,
        },
    )
    .await?;
    // Keep `_tunnel` alive for the proxy's lifetime.
    proxy::serve(opts.bind, netstack).await
}

/// Try each obfuscation mode in turn until a tunnel comes up and passes the
/// connectivity test.
pub(crate) async fn bring_up(
    ident: &Identity,
    endpoint: SocketAddr,
    reserved: [u8; 3],
    attempts: &[JunkConfig],
    dns: IpAddr,
    tuning: Tuning,
) -> Result<(NetStack, Tunnel)> {
    for (i, junk) in attempts.iter().enumerate() {
        info!(
            attempt = i + 1,
            enabled = junk.enabled,
            %endpoint,
            "bringing up tunnel"
        );
        if let Some(pair) =
            setup_tunnel(ident, endpoint, reserved, junk.clone(), dns, tuning).await?
        {
            return Ok(pair);
        }
    }
    Err(anyhow!(
        "could not establish a tunnel with any obfuscation mode"
    ))
}

/// Start a WARP engine WITHOUT a netstack, trying each obfuscation mode until the
/// handshake completes. Returns the tunnel plus channels for feeding packets to
/// encapsulate / receiving decapsulated packets. Used by TUN mode and gool's outer.
pub(crate) async fn start_engine(
    ident: &Identity,
    endpoint: SocketAddr,
    reserved: [u8; 3],
    attempts: &[JunkConfig],
    keepalive: u16,
) -> Result<EngineChannels> {
    // Validate keys up front (rebuilt per attempt since StaticSecret is consumed).
    let _ = key::static_secret_from_b64(&ident.private_key)?;
    let _ = key::public_from_b64(&ident.peer()?.public_key)?;

    for (i, junk) in attempts.iter().enumerate() {
        info!(attempt = i + 1, enabled = junk.enabled, %endpoint, "handshake");
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let io = EngineIo {
            inbound_tx,
            outbound_rx,
        };
        let cfg = WgConfig {
            private_key: key::static_secret_from_b64(&ident.private_key)?,
            peer_public: key::public_from_b64(&ident.peer()?.public_key)?,
            preshared_key: None,
            endpoint,
            keepalive: Some(keepalive),
            reserved,
            junk: junk.clone(),
            bind: None,
        };
        let mut tunnel = Tunnel::start(cfg, io);
        if tunnel.wait_connected(Duration::from_secs(12)).await {
            info!("handshake complete");
            return Ok((tunnel, outbound_tx, inbound_rx));
        }
        warn!("handshake did not complete; trying next obfuscation mode");
    }
    Err(anyhow!(
        "could not establish a tunnel with any obfuscation mode"
    ))
}

/// Build a tunnel + netstack, verify it carries traffic. Returns `None` if it fails
/// the connectivity test so the caller can try the next obfuscation mode.
pub(crate) async fn setup_tunnel(
    ident: &Identity,
    endpoint: SocketAddr,
    reserved: [u8; 3],
    junk: JunkConfig,
    dns: IpAddr,
    tuning: Tuning,
) -> Result<Option<(NetStack, Tunnel)>> {
    let private_key =
        key::static_secret_from_b64(&ident.private_key).context("parsing identity private key")?;
    let peer_public =
        key::public_from_b64(&ident.peer()?.public_key).context("parsing peer public key")?;
    let addresses = interface_addresses(ident)?;

    let (netstack, io) = NetStack::new(addresses, vec![dns], tuning.mtu, tuning.tcp_buf);

    let cfg = WgConfig {
        private_key,
        peer_public,
        preshared_key: None,
        endpoint,
        keepalive: Some(tuning.keepalive),
        reserved,
        junk,
        bind: None,
    };

    let mut tunnel = Tunnel::start(cfg, io);

    if !tunnel.wait_connected(Duration::from_secs(12)).await {
        warn!("wireguard handshake did not complete");
        return Ok(None);
    }
    if !connectivity_ok(&netstack).await {
        warn!("tunnel connectivity test failed");
        return Ok(None);
    }

    info!(%endpoint, "tunnel established");
    Ok(Some((netstack, tunnel)))
}

/// Probe the data path by doing a tiny HTTP exchange to 1.1.1.1 through the tunnel.
pub(crate) async fn connectivity_ok(netstack: &NetStack) -> bool {
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 80);
    let fut = async {
        let mut tcp = netstack.connect(target).await.ok()?;
        tcp.write(
            b"HEAD /cdn-cgi/trace HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n"
                .to_vec(),
        )
        .ok()?;
        tcp.recv().await
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(6), fut).await,
        Ok(Some(_))
    )
}

/// Parse the identity's interface addresses (v4 and v6 if present).
pub(crate) fn interface_addresses(ident: &Identity) -> Result<Vec<IpAddr>> {
    let mut addrs = Vec::new();
    let v4 = strip_prefix(&ident.config.interface.addresses.v4);
    let v6 = strip_prefix(&ident.config.interface.addresses.v6);
    if !v4.is_empty() {
        addrs.push(
            v4.parse::<IpAddr>()
                .context("parsing interface v4 address")?,
        );
    }
    if !v6.is_empty() {
        addrs.push(
            v6.parse::<IpAddr>()
                .context("parsing interface v6 address")?,
        );
    }
    if addrs.is_empty() {
        return Err(anyhow!("identity has no interface addresses"));
    }
    Ok(addrs)
}

fn strip_prefix(s: &str) -> &str {
    s.split('/').next().unwrap_or("").trim()
}
