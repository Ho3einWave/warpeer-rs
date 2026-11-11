mod app;
mod gool;
mod netstack;
mod obfs;
mod proxy;
mod scanner;
mod tunmode;
mod warp;
mod wg;
mod wgconfig;

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::obfs::JunkConfig;

/// Userspace Cloudflare WARP client (warp + warp-in-warp) with junk-packet
/// obfuscation (warp-plus trick + AmneziaWG Jc/Jmin/Jmax/Jdelay).
#[derive(Parser, Debug)]
#[command(name = "warpeer", version)]
struct Cli {
    /// Enable verbose (debug) logging
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Only use IPv4 for the random warp endpoint
    #[arg(short = '4')]
    v4: bool,
    /// Only use IPv6 for the random warp endpoint
    #[arg(short = '6')]
    v6: bool,

    /// Proxy bind address (SOCKS5/SOCKS4/HTTP on one port)
    #[arg(short = 'b', long, default_value = "127.0.0.1:8086")]
    bind: String,

    /// WARP endpoint (host:port); random if omitted
    #[arg(short = 'e', long, default_value = "")]
    endpoint: String,

    /// WARP+ license key
    #[arg(short = 'k', long, default_value = "")]
    key: String,

    /// DNS resolver address (used inside the tunnel)
    #[arg(long, default_value = "1.1.1.1")]
    dns: String,

    /// Enable gool mode (warp-in-warp)
    #[arg(long)]
    gool: bool,

    /// Standard WireGuard config to use as the outer tunnel; implies --gool
    #[arg(long, value_name = "FILE", conflicts_with = "inner_config")]
    outer_config: Option<PathBuf>,

    /// Standard WireGuard config to use as the inner tunnel; implies --gool
    #[arg(long, value_name = "FILE", conflicts_with = "outer_config")]
    inner_config: Option<PathBuf>,

    /// Enable TUN mode: route ALL system traffic through WARP (Windows; needs Administrator + wintun.dll)
    #[arg(long)]
    tun: bool,

    /// Enable warp endpoint scanning (find responsive low-RTT endpoints)
    #[arg(long)]
    scan: bool,

    /// Max desirable handshake RTT for the scanner, in milliseconds
    #[arg(long, default_value_t = 1000)]
    rtt: u64,

    /// Tunnel MTU for the userspace netstack (bytes)
    #[arg(long, default_value_t = app::SINGLE_MTU)]
    mtu: usize,

    /// Per-direction TCP buffer per connection, in KiB (uses 2x this much RAM per connection)
    #[arg(long, default_value_t = netstack::DEFAULT_TCP_BUF / 1024)]
    tcp_buf: usize,

    /// Cache directory for the WARP identity
    #[arg(long, default_value = "")]
    cache_dir: String,

    /// WARP reserved value: "a,b,c" or "random" (defaults to the identity client_id)
    #[arg(long, default_value = "")]
    reserved: String,

    // --- obfuscation knobs ---
    /// Disable junk-packet obfuscation entirely
    #[arg(long)]
    no_obfs: bool,

    /// AmneziaWG junk packet count (Jc). When > 0, uses Amnezia junk instead of the trick presets.
    #[arg(long, default_value_t = 0)]
    jc: u32,
    /// AmneziaWG junk minimum size in bytes (Jmin)
    #[arg(long, default_value_t = 40)]
    jmin: usize,
    /// AmneziaWG junk maximum size in bytes (Jmax)
    #[arg(long, default_value_t = 120)]
    jmax: usize,
    /// AmneziaWG delay between junk packets in ms (Jdelay)
    #[arg(long, default_value_t = 10)]
    jdelay: u64,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(e) = real_main(cli).await {
        error!("{e:#}");
        std::process::exit(1);
    }
}

async fn real_main(cli: Cli) -> Result<()> {
    let level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level)),
        )
        .init();

    if cli.v4 && cli.v6 {
        return Err(anyhow!("can't force both -4 and -6"));
    }
    if !(1280..=1440).contains(&cli.mtu) {
        return Err(anyhow!("--mtu must be between 1280 and 1440 bytes"));
    }
    if cli.tcp_buf < 64 {
        return Err(anyhow!("--tcp-buf must be at least 64 KiB"));
    }
    let has_custom_config = cli.outer_config.is_some() || cli.inner_config.is_some();
    let gool = cli.gool || has_custom_config;
    if gool && cli.v6 {
        return Err(anyhow!(
            "warp-in-warp (--gool/--outer-config/--inner-config) currently requires an IPv4 WARP endpoint"
        ));
    }
    let (use_v4, use_v6) = if gool && !cli.v4 {
        // The gool shim wraps inner datagrams in IPv4 frames and the outer tunnel
        // needs an IPv4 endpoint, so never pick IPv6 for it (also applies to --scan).
        (true, false)
    } else if !cli.v4 && !cli.v6 {
        (true, true)
    } else {
        (cli.v4, cli.v6)
    };

    let bind: SocketAddr = cli.bind.parse().context("invalid bind address")?;
    let dns: IpAddr = cli.dns.parse().context("invalid DNS address")?;

    let endpoint: SocketAddr = if cli.endpoint.is_empty() {
        warp::endpoint::random_warp_endpoint(use_v4, use_v6)?
    } else {
        cli.endpoint
            .parse()
            .context("invalid endpoint (expected ip:port)")?
    };

    let reserved = if cli.reserved.is_empty() {
        None
    } else {
        Some(parse_reserved(&cli.reserved)?)
    };

    let obfs_attempts = build_obfs_attempts(&cli);

    let cache_dir = resolve_cache_dir(&cli.cache_dir);

    // gool needs two endpoints; warp uses one.
    let scan = if cli.scan {
        Some(scanner::ScanOptions {
            v4: use_v4,
            v6: use_v6,
            max_rtt: std::time::Duration::from_millis(cli.rtt),
            count: if cli.gool && !has_custom_config { 2 } else { 1 },
            // A light junk burst — enough to open the path/NAT like the live tunnel does,
            // but far smaller than the full trick so probing stays fast.
            junk: JunkConfig::amnezia(6, 40, 100, 10),
        })
    } else {
        None
    };

    info!(%endpoint, %bind, gool, scan = cli.scan, "starting warpeer");

    let opts = app::Options {
        bind,
        license: cli.key,
        dns,
        cache_dir,
        reserved,
        obfs_attempts,
        gool,
        outer_config: cli.outer_config,
        inner_config: cli.inner_config,
        tun: cli.tun,
        tcp_buf: cli.tcp_buf * 1024,
        mtu: cli.mtu,
        endpoints: vec![endpoint],
        scan,
    };

    tokio::select! {
        r = app::run(opts) => r,
        _ = tokio::signal::ctrl_c() => {
            info!("received ctrl-c, shutting down");
            Ok(())
        }
    }
}

fn build_obfs_attempts(cli: &Cli) -> Vec<JunkConfig> {
    if cli.no_obfs {
        vec![JunkConfig::disabled()]
    } else if cli.jc > 0 {
        vec![JunkConfig::amnezia(cli.jc, cli.jmin, cli.jmax, cli.jdelay)]
    } else {
        // warp-plus behaviour: try trick t1, then t2.
        vec![JunkConfig::trick_t1(), JunkConfig::trick_t2()]
    }
}

fn parse_reserved(s: &str) -> Result<[u8; 3]> {
    if s == "random" {
        use rand::Rng;
        let mut r = [0u8; 3];
        rand::thread_rng().fill(&mut r);
        return Ok(r);
    }
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() != 3 {
        return Err(anyhow!("reserved must be 'a,b,c' or 'random'"));
    }
    let mut out = [0u8; 3];
    for (i, p) in parts.iter().enumerate() {
        out[i] = p
            .trim()
            .parse::<u8>()
            .context("reserved values must be 0-255")?;
    }
    Ok(out)
}

fn resolve_cache_dir(explicit: &str) -> PathBuf {
    if !explicit.is_empty() {
        return PathBuf::from(explicit);
    }
    if let Some(dirs) = directories::ProjectDirs::from("", "", "warpeer") {
        return dirs.cache_dir().to_path_buf();
    }
    PathBuf::from("warpeer_cache")
}
