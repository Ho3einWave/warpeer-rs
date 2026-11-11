//! WARP endpoint scanner.
//!
//! Mirrors warp-plus `ipscanner`: probe candidate WARP IP:port pairs by performing
//! a real WireGuard handshake (junk burst first, then a Noise IK initiation) and
//! measuring the round-trip time to the handshake response. Responsive low-RTT
//! endpoints are returned, sorted fastest-first.
//!
//! Unlike warp-plus' full-period LCG sweep, this samples candidates at random — which
//! finds a handful of good endpoints quickly, which is all the client needs.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use boringtun::noise::{Tunn, TunnResult};
use rand::Rng;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::Instant;
use tracing::{debug, info};

use crate::obfs::JunkConfig;
use crate::warp::{endpoint, key, Identity};

pub struct ScanOptions {
    pub v4: bool,
    pub v6: bool,
    /// Maximum acceptable handshake RTT.
    pub max_rtt: Duration,
    /// Number of endpoints to return (gool needs 2).
    pub count: usize,
    /// Junk obfuscation to use during probing (kept light by default).
    pub junk: JunkConfig,
}

const CANDIDATES: usize = 512;
const CONCURRENCY: usize = 128;
const BUDGET: Duration = Duration::from_secs(30);

/// Scan for responsive WARP endpoints using the identity's keys.
pub async fn find_endpoints(ident: &Identity, opts: ScanOptions) -> Result<Vec<SocketAddr>> {
    let priv_b64 = ident.private_key.clone();
    let pub_b64 = ident.peer()?.public_key.clone();
    let reserved = ident.reserved().unwrap_or([0, 0, 0]);
    let junk = Arc::new(opts.junk.clone());

    // Per-probe wait: at least a bit above the RTT threshold so good endpoints aren't
    // cut off by junk-burst latency.
    let probe_timeout = opts.max_rtt.max(Duration::from_millis(1500));

    info!(max_rtt = ?opts.max_rtt, count = opts.count, "scanning for warp endpoints");

    let pool = generate_candidates(opts.v4, opts.v6, CANDIDATES);
    let sem = Arc::new(Semaphore::new(CONCURRENCY));
    let mut set: JoinSet<Option<(SocketAddr, Duration)>> = JoinSet::new();

    for addr in pool {
        let priv_b64 = priv_b64.clone();
        let pub_b64 = pub_b64.clone();
        let junk = junk.clone();
        let sem = sem.clone();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            let rtt = handshake_rtt(addr, &priv_b64, &pub_b64, reserved, &junk, probe_timeout)
                .await
                .ok()?;
            Some((addr, rtt))
        });
    }

    let want = (opts.count * 4).max(8);
    let mut found: Vec<(SocketAddr, Duration)> = Vec::new();
    let deadline = Instant::now() + BUDGET;

    loop {
        match tokio::time::timeout_at(deadline, set.join_next()).await {
            Ok(Some(Ok(Some((addr, rtt))))) => {
                if rtt <= opts.max_rtt {
                    debug!(%addr, ?rtt, "endpoint responded");
                    found.push((addr, rtt));
                    if found.len() >= want {
                        break;
                    }
                }
            }
            Ok(Some(_)) => {}  // failed probe or join error
            Ok(None) => break, // pool exhausted
            Err(_) => break,   // budget elapsed
        }
    }
    set.abort_all();

    found.sort_by_key(|(_, rtt)| *rtt);
    if found.is_empty() {
        return Err(anyhow!("scanner found no responsive warp endpoints"));
    }

    let result: Vec<SocketAddr> = found.iter().take(opts.count).map(|(a, _)| *a).collect();
    for (addr, rtt) in found.iter().take(opts.count) {
        info!(%addr, ?rtt, "selected warp endpoint");
    }
    Ok(result)
}

/// Probe one endpoint: junk burst, then a WireGuard handshake initiation; return the
/// RTT to a valid handshake response.
async fn handshake_rtt(
    addr: SocketAddr,
    priv_b64: &str,
    pub_b64: &str,
    reserved: [u8; 3],
    junk: &JunkConfig,
    timeout: Duration,
) -> Result<Duration> {
    let sk = key::static_secret_from_b64(priv_b64)?;
    let pk = key::public_from_b64(pub_b64)?;
    let index: u32 = rand::thread_rng().gen();
    let mut tunn =
        Tunn::new(sk, pk, None, None, index, None).map_err(|e| anyhow!("tunn init: {e}"))?;

    let bind = if addr.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(addr).await?;

    // Junk burst (its latency is intentionally excluded from the measured RTT).
    for pkt in junk.build_burst() {
        socket.send(&pkt).await?;
        tokio::time::sleep(junk.delay()).await;
    }

    let mut buf = vec![0u8; 256];
    let init = match tunn.format_handshake_initiation(&mut buf, false) {
        TunnResult::WriteToNetwork(p) => p,
        _ => return Err(anyhow!("could not format handshake initiation")),
    };
    apply_reserved(init, reserved);

    let t0 = Instant::now();
    socket.send(init).await?;

    let mut resp = vec![0u8; 2048];
    let n = match tokio::time::timeout(timeout, socket.recv(&mut resp)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            debug!(%addr, "recv error: {e}");
            return Err(anyhow!("recv: {e}"));
        }
        Err(_) => {
            debug!(%addr, "handshake timed out");
            return Err(anyhow!("handshake timed out"));
        }
    };
    let rtt = t0.elapsed();

    clear_reserved(&mut resp[..n]);
    let mut d = vec![0u8; 2048];
    match tunn.decapsulate(Some(addr.ip()), &resp[..n], &mut d) {
        TunnResult::Err(e) => {
            debug!(%addr, "decapsulate rejected response ({n} bytes): {e:?}");
            Err(anyhow!("invalid handshake response: {e:?}"))
        }
        _ => Ok(rtt),
    }
}

fn generate_candidates(v4: bool, v6: bool, n: usize) -> Vec<SocketAddr> {
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        match endpoint::random_warp_endpoint(v4, v6) {
            Ok(addr) => out.push(addr),
            Err(_) => break,
        }
    }
    out
}

fn apply_reserved(pkt: &mut [u8], reserved: [u8; 3]) {
    if pkt.len() > 3 && pkt[0] >= 1 && pkt[0] <= 4 {
        pkt[1..4].copy_from_slice(&reserved);
    }
}

fn clear_reserved(pkt: &mut [u8]) {
    if pkt.len() > 3 && pkt[0] >= 1 && pkt[0] <= 4 {
        pkt[1] = 0;
        pkt[2] = 0;
        pkt[3] = 0;
    }
}
