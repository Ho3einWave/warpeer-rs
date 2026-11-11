//! MASQUE mode: Cloudflare WARP over CONNECT-IP (RFC 9484) inside HTTP/3.
//!
//! Instead of WireGuard, the device is enrolled with an ECDSA P-256 key
//! (`key_type=secp256r1`, `tunnel_type=masque`) and connects to Cloudflare's
//! MASQUE edge with mutual TLS. IP packets are carried as HTTP/3 datagrams on a
//! CONNECT-IP request; the netstack/proxy above it are unchanged.
//!
//! The transport itself is the MIT-licensed `usque-rs` implementation, pinned to
//! a commit. Cloudflare uses the non-standard `cf-connect-ip` protocol token, so
//! a patched `h3` lives under `vendor/h3` (see `[patch.crates-io]`).

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use usque_config::Config;
use usque_masque::{connect_tunnel, ConnectOptions, PacketSession};

use crate::app::{self, Options};
use crate::netstack::{EngineIo, NetStack};
use crate::proxy;

/// The MASQUE edge listens on 443 (QUIC/HTTP3).
const CONNECT_PORT: u16 = 443;
/// Cloudflare's edge reaps idle sessions well before QUIC's advertised idle
/// timeout; 10 s keeps the session alive without meaningful overhead.
const KEEPALIVE: Duration = Duration::from_secs(10);
/// QUIC handshakes complete in well under a second on a working path; a short
/// timeout lets us fall back to HTTP/2 when UDP/443 is filtered.
const H3_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const H2_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const INITIAL_BACKOFF: Duration = Duration::from_secs(2);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const MASQUE_CONFIG_FILE: &str = "masque.json";

/// Run the whole MASQUE path: config (register on first use), tunnel, netstack,
/// connectivity check and the local proxy.
pub async fn run(opts: &Options) -> Result<()> {
    // Must happen before any rustls client is built: usque-crypto uses the
    // aws-lc-rs provider, and installing it after another provider is an error.
    usque_crypto::init();

    let config = load_or_register(opts).await?;
    let addresses = interface_addresses(&config)?;
    let client = MasqueClient::new(&config, opts)?;

    info!(
        endpoint_v4 = %client.endpoint_h3,
        endpoint_h2 = %client.endpoint_h2,
        ?addresses,
        "connecting MASQUE tunnel"
    );
    let session = client
        .connect()
        .await
        .context("initial MASQUE connection failed")?;

    let (netstack, io) = NetStack::new(addresses, vec![opts.dns], opts.mtu, opts.tcp_buf);
    tokio::spawn(engine_loop(client, session, io));

    if !app::connectivity_ok(&netstack).await {
        return Err(anyhow!(
            "MASQUE CONNECT succeeded but the data path did not pass the connectivity test"
        ));
    }

    info!(bind = %opts.bind, "MASQUE tunnel established");
    proxy::serve(opts.bind, netstack).await
}

/// Load the existing MASQUE config, or register + enroll a new device and save it.
async fn load_or_register(opts: &Options) -> Result<Config> {
    if let Some(path) = &opts.masque_config {
        return Config::load(path)
            .with_context(|| format!("loading MASQUE config {}", path.display()));
    }

    let path = opts.cache_dir.join(MASQUE_CONFIG_FILE);
    if path.exists() {
        info!(path = %path.display(), "loading existing MASQUE config");
        return Config::load(&path)
            .with_context(|| format!("loading MASQUE config {}", path.display()));
    }

    register_and_save(&path, &opts.license).await
}

/// Register a WARP device, switch it to MASQUE mode by enrolling an ECDSA key,
/// and persist the resulting usque-compatible config.
async fn register_and_save(path: &Path, license: &str) -> Result<Config> {
    info!("no MASQUE config found; registering a new WARP device (accepting the Cloudflare ToS)");

    let http = usque_cloudflare_api::CloudflareClient::new();
    let account = tokio::time::timeout(
        Duration::from_secs(60),
        usque_cloudflare_api::register(
            &http,
            usque_cloudflare_api::DEFAULT_MODEL,
            usque_cloudflare_api::DEFAULT_LOCALE,
            None,
            true,
        ),
    )
    .await
    .map_err(|_| anyhow!("WARP registration timed out"))?
    .context("registering with the WARP API")?;

    let (private_der, public_der) = usque_crypto::generate_ec_keypair()?;
    let token = account.token.clone().unwrap_or_default();
    if token.is_empty() {
        return Err(anyhow!("WARP API returned no access token"));
    }

    info!("enrolling the MASQUE device key");
    let updated = tokio::time::timeout(
        Duration::from_secs(60),
        usque_cloudflare_api::enroll_key(&http, &account.id, &token, &public_der, "warpeer"),
    )
    .await
    .map_err(|_| anyhow!("MASQUE key enrollment timed out"))?
    .map_err(|e| anyhow!("enrolling MASQUE key: {e}"))?;

    let peer = updated
        .config
        .peers
        .first()
        .ok_or_else(|| anyhow!("registration response contains no peer"))?;

    let mut config = Config {
        private_key: B64.encode(private_der),
        endpoint_v4: usque_config::parse_endpoint_v4(&peer.endpoint.v4),
        endpoint_v6: usque_config::parse_endpoint_v6(&peer.endpoint.v6),
        endpoint_h2_v4: usque_config::DEFAULT_ENDPOINT_H2_V4.to_string(),
        endpoint_h2_v6: String::new(),
        endpoint_pub_key: peer.public_key.clone(),
        license: updated.account.license.clone(),
        id: updated.id.clone(),
        access_token: token,
        ipv4: updated.config.interface.addresses.v4.clone(),
        ipv6: updated.config.interface.addresses.v6.clone(),
    };

    // Licensing is best-effort: the WG and MASQUE modes register separate
    // devices, so a WARP+ key may need to be moved to the new device.
    if !license.is_empty() {
        match crate::warp::api::WarpApi::new() {
            Ok(api) => match api
                .update_account(&config.access_token, &config.id, license)
                .await
            {
                Ok(account) => config.license = account.license,
                Err(e) => warn!("could not apply the WARP+ license to the MASQUE device: {e}"),
            },
            Err(e) => warn!("could not create the WARP API client: {e}"),
        }
    }

    save_config(path, &config)?;
    info!(path = %path.display(), "saved MASQUE config");
    Ok(config)
}

fn save_config(path: &Path, config: &Config) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let json = serde_json::to_vec_pretty(config)?;
    crate::warp::identity::write_private(path, &json)
}

/// Interface addresses assigned to the device (as stored in the config).
fn interface_addresses(config: &Config) -> Result<Vec<IpAddr>> {
    let mut out = Vec::new();
    for raw in [&config.ipv4, &config.ipv6] {
        let value = raw.split('/').next().unwrap_or("").trim();
        if value.is_empty() {
            continue;
        }
        match value.parse::<IpAddr>() {
            Ok(ip) => out.push(ip),
            Err(_) => warn!(address = %value, "ignoring invalid MASQUE interface address"),
        }
    }
    if out.is_empty() {
        return Err(anyhow!("MASQUE config has no IPv4/IPv6 interface address"));
    }
    Ok(out)
}

/// The MASQUE edge address from the config, honoring `-4`/`-6` and the
/// transport (HTTP/2 uses the `endpoint_h2_*` addresses).
fn select_endpoint(
    config: &Config,
    use_v4: bool,
    use_v6: bool,
    use_http2: bool,
) -> Result<SocketAddr> {
    let (v4, v6) = if use_http2 {
        (config.endpoint_h2_v4.trim(), config.endpoint_h2_v6.trim())
    } else {
        (config.endpoint_v4.trim(), config.endpoint_v6.trim())
    };
    // Cloudflare's HTTP/2 endpoint is a fixed address when the config omits it.
    let v4 = if use_http2 && v4.is_empty() {
        usque_config::DEFAULT_ENDPOINT_H2_V4
    } else {
        v4
    };

    let pick = |value: &str| -> Result<SocketAddr> {
        let ip: IpAddr = value
            .trim_matches(['[', ']'])
            .parse()
            .with_context(|| format!("invalid MASQUE endpoint {value:?}"))?;
        Ok(SocketAddr::new(ip, CONNECT_PORT))
    };

    match (use_v4, use_v6) {
        (true, false) => pick(v4).context("MASQUE config has no IPv4 endpoint (remove -4)"),
        (false, true) => pick(v6).context("MASQUE config has no IPv6 endpoint (remove -6)"),
        _ => {
            if !v4.is_empty() {
                pick(v4)
            } else if !v6.is_empty() {
                pick(v6)
            } else {
                Err(anyhow!("MASQUE config has no usable endpoint"))
            }
        }
    }
}

/// Everything needed to (re)establish the HTTP/3 or HTTP/2 session.
struct MasqueClient {
    tls_h3: Arc<rustls::ClientConfig>,
    tls_h2: Arc<rustls::ClientConfig>,
    quiche: Arc<usque_crypto::QuicheClientCredentials>,
    peer: usque_crypto::PeerPublicKey,
    endpoint_h3: SocketAddr,
    endpoint_h2: SocketAddr,
    sni: String,
    /// Set once HTTP/2 turns out to be the working transport (UDP/443 filtered);
    /// avoids paying the HTTP/3 timeout on every reconnect.
    prefer_h2: AtomicBool,
}

impl MasqueClient {
    fn new(config: &Config, opts: &Options) -> Result<Self> {
        let signing_key = usque_crypto::decode_private_key(&config.private_key)
            .context("parsing the MASQUE private key")?;
        let peer = usque_crypto::decode_endpoint_public_key(&config.endpoint_pub_key)
            .context("parsing the MASQUE endpoint public key")?;
        let sni = usque_cloudflare_api::CONNECT_SNI.to_string();

        let build_tls = |alpn: &[u8]| -> Result<Arc<rustls::ClientConfig>> {
            usque_crypto::build_rustls_config(
                &signing_key,
                usque_crypto::TlsOptions {
                    sni: sni.clone(),
                    insecure: false,
                    peer_public_key: peer.clone(),
                    alpn: vec![alpn.to_vec()],
                },
            )
            .context("building the MASQUE TLS config")
        };

        let endpoint_h3 = select_endpoint(config, opts.use_v4, opts.use_v6, false)?;
        // HTTP/2 can fall back to the HTTP/3 edge if the config lacks an h2 one.
        let endpoint_h2 =
            select_endpoint(config, opts.use_v4, opts.use_v6, true).unwrap_or(endpoint_h3);

        Ok(Self {
            tls_h3: build_tls(b"h3")?,
            tls_h2: build_tls(b"h2")?,
            quiche: Arc::new(usque_crypto::prepare_quiche_client_credentials(
                &signing_key,
            )?),
            peer,
            endpoint_h3,
            endpoint_h2,
            sni,
            prefer_h2: AtomicBool::new(opts.masque_h2),
        })
    }

    /// Connect over HTTP/3, falling back to HTTP/2 when UDP/443 is filtered.
    async fn connect(&self) -> Result<Box<dyn PacketSession>> {
        if self.prefer_h2.load(Ordering::Relaxed) {
            return self.connect_h2().await;
        }

        match tokio::time::timeout(H3_CONNECT_TIMEOUT, self.connect_h3()).await {
            Ok(Ok(session)) => Ok(session),
            Ok(Err(e)) => {
                warn!("HTTP/3 connect failed ({e}); falling back to HTTP/2");
                self.connect_h2().await
            }
            Err(_) => {
                warn!("HTTP/3 connect timed out (UDP/443 filtered?); falling back to HTTP/2");
                self.connect_h2().await
            }
        }
    }

    async fn connect_h3(&self) -> Result<Box<dyn PacketSession>> {
        let session = connect_tunnel(&self.options(false)).await?;
        self.prefer_h2.store(false, Ordering::Relaxed);
        info!(endpoint = %self.endpoint_h3, "MASQUE transport: HTTP/3 (QUIC)");
        Ok(session)
    }

    async fn connect_h2(&self) -> Result<Box<dyn PacketSession>> {
        let session = tokio::time::timeout(H2_CONNECT_TIMEOUT, connect_tunnel(&self.options(true)))
            .await
            .map_err(|_| anyhow!("HTTP/2 MASQUE connect timed out"))??;
        self.prefer_h2.store(true, Ordering::Relaxed);
        info!(endpoint = %self.endpoint_h2, "MASQUE transport: HTTP/2 (TLS/TCP)");
        Ok(session)
    }

    fn options(&self, use_http2: bool) -> ConnectOptions {
        ConnectOptions {
            tls_config: if use_http2 {
                self.tls_h2.clone()
            } else {
                self.tls_h3.clone()
            },
            quiche_credentials: self.quiche.clone(),
            insecure: false,
            peer_public_key: self.peer.clone(),
            endpoint: if use_http2 {
                self.endpoint_h2
            } else {
                self.endpoint_h3
            },
            sni: self.sni.clone(),
            use_http2,
            keepalive_period: KEEPALIVE,
            initial_packet_size: 0,
            connect_uri: usque_cloudflare_api::CONNECT_URI.to_string(),
        }
    }
}

/// Bridge the CONNECT-IP session to the netstack, reconnecting on failure.
async fn engine_loop(client: MasqueClient, mut session: Box<dyn PacketSession>, io: EngineIo) {
    let EngineIo {
        inbound_tx,
        mut outbound_rx,
    } = io;
    let mut backoff = INITIAL_BACKOFF;

    loop {
        match pump(&mut *session, &inbound_tx, &mut outbound_rx).await {
            PumpEnd::NetstackGone => {
                debug!("netstack dropped; stopping the MASQUE engine");
                return;
            }
            PumpEnd::Closed(reason) => warn!("MASQUE session ended: {reason}"),
        }

        let _ = session.close().await;

        loop {
            // Packets queued while the tunnel was down are stale; the netstack
            // will retransmit whatever still matters once we are back.
            while outbound_rx.try_recv().is_ok() {}
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);

            match client.connect().await {
                Ok(new_session) => {
                    info!("MASQUE reconnected");
                    session = new_session;
                    backoff = INITIAL_BACKOFF;
                    break;
                }
                Err(e) => warn!("MASQUE reconnect failed: {e}"),
            }
        }
    }
}

enum PumpEnd {
    NetstackGone,
    Closed(String),
}

/// Forward packets in both directions until the session or the netstack goes away.
async fn pump(
    session: &mut dyn PacketSession,
    inbound_tx: &mpsc::UnboundedSender<Vec<u8>>,
    outbound_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
) -> PumpEnd {
    loop {
        tokio::select! {
            packet = outbound_rx.recv() => {
                let Some(mut packet) = packet else {
                    return PumpEnd::NetstackGone;
                };
                if let Err(e) = usque_masque::decrement_ttl(&mut packet) {
                    debug!("skipping outbound packet: {e}");
                    continue;
                }
                match session.write_packet(&packet).await {
                    Ok(Some(icmp)) => {
                        let _ = inbound_tx.send(icmp.to_vec());
                    }
                    Ok(None) => {}
                    Err(e) => return PumpEnd::Closed(e.to_string()),
                }
            }
            read = session.read_packet() => match read {
                Ok(Some(packet)) => {
                    let _ = inbound_tx.send(packet.to_vec());
                }
                Ok(None) => return PumpEnd::Closed("session closed by peer".into()),
                Err(e) => return PumpEnd::Closed(e.to_string()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            private_key: String::new(),
            endpoint_v4: "162.159.198.1".into(),
            endpoint_v6: "2606:4700:103::1".into(),
            endpoint_h2_v4: String::new(),
            endpoint_h2_v6: String::new(),
            endpoint_pub_key: String::new(),
            license: String::new(),
            id: String::new(),
            access_token: String::new(),
            ipv4: "100.96.0.2/32".into(),
            ipv6: "2606:4700:110:abcd::2/128".into(),
        }
    }

    #[test]
    fn parses_interface_addresses_and_strips_prefixes() {
        let addrs = interface_addresses(&config()).unwrap();
        assert_eq!(
            addrs,
            vec![
                "100.96.0.2".parse::<IpAddr>().unwrap(),
                "2606:4700:110:abcd::2".parse::<IpAddr>().unwrap()
            ]
        );
    }

    #[test]
    fn rejects_config_without_addresses() {
        let mut cfg = config();
        cfg.ipv4.clear();
        cfg.ipv6.clear();
        assert!(interface_addresses(&cfg).is_err());
    }

    #[test]
    fn selects_endpoints_by_family() {
        let cfg = config();
        assert_eq!(
            select_endpoint(&cfg, true, false, false).unwrap(),
            "162.159.198.1:443".parse().unwrap()
        );
        assert_eq!(
            select_endpoint(&cfg, false, true, false).unwrap(),
            "[2606:4700:103::1]:443".parse().unwrap()
        );
        // Neither forced: prefer IPv4.
        assert_eq!(
            select_endpoint(&cfg, true, true, false).unwrap(),
            "162.159.198.1:443".parse().unwrap()
        );
    }

    #[test]
    fn selects_the_h2_endpoint_for_http2() {
        let cfg = config();
        // The test config has no h2 endpoint, so the fixed Cloudflare one is used.
        assert_eq!(
            select_endpoint(&cfg, true, false, true).unwrap(),
            format!("{}:443", usque_config::DEFAULT_ENDPOINT_H2_V4)
                .parse()
                .unwrap()
        );
    }

    #[test]
    fn forced_family_must_exist() {
        let mut cfg = config();
        cfg.endpoint_v4.clear();
        assert!(select_endpoint(&cfg, true, false, false).is_err());
        assert!(select_endpoint(&cfg, false, true, false).is_ok());
    }
}
