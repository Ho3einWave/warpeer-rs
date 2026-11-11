//! Mixed proxy: accepts HTTP-proxy (CONNECT + plain), SOCKS5 and SOCKS4 on the same
//! port, all dialed through the netstack (with DNS resolved through the tunnel).
//!
//! The protocol is detected from the first byte of the client connection:
//!   * `0x05` → SOCKS5
//!   * `0x04` → SOCKS4 / SOCKS4a
//!   * anything else (an ASCII HTTP method) → HTTP proxy

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use crate::netstack::{NetStack, TunnelTcp};

/// Start the mixed proxy bound to `bind`. Runs until the process exits.
pub async fn serve(bind: SocketAddr, netstack: NetStack) -> Result<()> {
    let listener = TcpListener::bind(bind).await?;
    let local = listener.local_addr()?;
    info!(address = %local, "serving proxy (http + socks5/4)");

    loop {
        let (client, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!("accept error: {e}");
                // Back off a little so a persistent error (e.g. EMFILE) does not spin.
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let ns = netstack.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(client, ns).await {
                debug!(%peer, "connection closed: {e}");
            }
        });
    }
}

async fn handle_client(mut client: TcpStream, netstack: NetStack) -> Result<()> {
    let first = client.read_u8().await?;
    match first {
        0x05 => handle_socks5(client, netstack).await,
        0x04 => handle_socks4(client, netstack).await,
        _ => handle_http(client, netstack, first).await,
    }
}

// ----------------------------------------------------------------------------
// Target resolution
// ----------------------------------------------------------------------------

async fn resolve_target(netstack: &NetStack, host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    // One retry to absorb a transient DNS hiccup under heavy parallel load.
    let mut last_err = None;
    for _ in 0..2 {
        match netstack.resolve(host).await {
            Ok(addrs) => {
                if let Some(ip) = addrs.first() {
                    return Ok(SocketAddr::new(*ip, port));
                }
                last_err = Some(anyhow!("no addresses for {host}"));
            }
            Err(e) => last_err = Some(anyhow!("{e}")),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("resolve failed for {host}")))
}

// ----------------------------------------------------------------------------
// HTTP proxy
// ----------------------------------------------------------------------------

async fn handle_http(mut client: TcpStream, netstack: NetStack, first: u8) -> Result<()> {
    let (head, leftover) = read_http_head(&mut client, first).await?;
    let text = String::from_utf8_lossy(&head);
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or_else(|| anyhow!("empty request"))?;

    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or_else(|| anyhow!("no method"))?;
    let target = parts.next().ok_or_else(|| anyhow!("no target"))?;

    if method.eq_ignore_ascii_case("CONNECT") {
        // HTTPS tunnelling: authority is host:port.
        let (host, port) = parse_authority(target, 443)?;
        let dst = match resolve_target(&netstack, &host, port).await {
            Ok(d) => d,
            Err(e) => {
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                return Err(e);
            }
        };
        let tunnel = match netstack.connect(dst).await {
            Ok(t) => t,
            Err(e) => {
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                return Err(anyhow!("connect {dst} failed: {e}"));
            }
        };
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        return pump(client, tunnel, leftover).await;
    }

    // Plain HTTP: target is an absolute URI (http://host[:port]/path).
    let (host, port, path) = match parse_http_url(target) {
        Ok(v) => v,
        Err(e) => {
            let _ = client
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .await;
            return Err(e);
        }
    };
    let dst = match resolve_target(&netstack, &host, port).await {
        Ok(d) => d,
        Err(e) => {
            let _ = client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await;
            return Err(e);
        }
    };
    let tunnel = match netstack.connect(dst).await {
        Ok(t) => t,
        Err(e) => {
            let _ = client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await;
            return Err(anyhow!("connect {dst} failed: {e}"));
        }
    };

    // Rebuild the request in origin-form, preserving headers (and ensuring Host).
    let mut rebuilt = format!("{method} {path} HTTP/1.1\r\n");
    let mut have_host = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if line.to_ascii_lowercase().starts_with("host:") {
            have_host = true;
        }
        // Drop proxy-specific hop-by-hop header.
        if line.to_ascii_lowercase().starts_with("proxy-connection:") {
            continue;
        }
        rebuilt.push_str(line);
        rebuilt.push_str("\r\n");
    }
    if !have_host {
        rebuilt.push_str(&format!("Host: {host}\r\n"));
    }
    rebuilt.push_str("\r\n");

    let mut initial = rebuilt.into_bytes();
    initial.extend_from_slice(&leftover);
    pump(client, tunnel, initial).await
}

/// Read up to (and including) the blank line terminating the HTTP headers.
/// Returns (header_block_without_terminator, leftover_body_bytes).
async fn read_http_head(client: &mut TcpStream, first: u8) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = vec![first];
    let mut tmp = [0u8; 4096];
    loop {
        if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
            let head = buf[..pos].to_vec();
            let leftover = buf[pos + 4..].to_vec();
            return Ok((head, leftover));
        }
        if buf.len() > 64 * 1024 {
            return Err(anyhow!("http header too large"));
        }
        let n = client.read(&mut tmp).await?;
        if n == 0 {
            return Err(anyhow!("eof before end of http headers"));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn parse_authority(s: &str, default_port: u16) -> Result<(String, u16)> {
    // Handle [v6]:port, host:port, or bare host.
    if let Some(rest) = s.strip_prefix('[') {
        let (h, p) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("bad v6 authority"))?;
        let port = p
            .strip_prefix(':')
            .and_then(|x| x.parse().ok())
            .unwrap_or(default_port);
        return Ok((h.to_string(), port));
    }
    match s.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
            Ok((h.to_string(), p.parse().unwrap_or(default_port)))
        }
        _ => Ok((s.to_string(), default_port)),
    }
}

fn parse_http_url(url: &str) -> Result<(String, u16, String)> {
    // Only plaintext absolute-form requests belong on this path; https is tunnelled
    // with CONNECT. Accepting an https:// URL here would send a cleartext request to
    // the origin.
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow!("unsupported URL (use CONNECT for https): {url}"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = parse_authority(authority, 80)?;
    Ok((host, port, path.to_string()))
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ----------------------------------------------------------------------------
// SOCKS5
// ----------------------------------------------------------------------------

async fn handle_socks5(mut client: TcpStream, netstack: NetStack) -> Result<()> {
    // Greeting (version byte already consumed): NMETHODS, METHODS...
    let nmethods = client.read_u8().await? as usize;
    if nmethods == 0 {
        return Err(anyhow!("socks5 client offered no auth methods"));
    }
    let mut methods = vec![0u8; nmethods];
    client.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        // No acceptable method: tell the client and stop.
        client.write_all(&[0x05, 0xff]).await?;
        return Err(anyhow!("socks5 client did not offer no-auth"));
    }
    client.write_all(&[0x05, 0x00]).await?; // no auth

    // Request: VER, CMD, RSV, ATYP, ADDR, PORT
    let ver = client.read_u8().await?;
    let cmd = client.read_u8().await?;
    let _rsv = client.read_u8().await?;
    let atyp = client.read_u8().await?;
    if ver != 0x05 {
        return Err(anyhow!("bad socks5 request version {ver}"));
    }
    if cmd != 0x01 {
        socks5_reply(&mut client, 0x07).await?; // command not supported
        return Err(anyhow!("unsupported SOCKS5 command {cmd}"));
    }

    let dst = match atyp {
        0x01 => {
            let mut b = [0u8; 4];
            client.read_exact(&mut b).await?;
            let port = client.read_u16().await?;
            SocketAddr::new(IpAddr::V4(b.into()), port)
        }
        0x04 => {
            let mut b = [0u8; 16];
            client.read_exact(&mut b).await?;
            let port = client.read_u16().await?;
            SocketAddr::new(IpAddr::V6(b.into()), port)
        }
        0x03 => {
            let len = client.read_u8().await? as usize;
            let mut name = vec![0u8; len];
            client.read_exact(&mut name).await?;
            let port = client.read_u16().await?;
            let host = String::from_utf8(name).map_err(|_| anyhow!("invalid domain"))?;
            match resolve_target(&netstack, &host, port).await {
                Ok(d) => d,
                Err(e) => {
                    socks5_reply(&mut client, 0x04).await?; // host unreachable
                    return Err(e);
                }
            }
        }
        other => {
            socks5_reply(&mut client, 0x08).await?;
            return Err(anyhow!("unsupported SOCKS5 atyp {other}"));
        }
    };

    match netstack.connect(dst).await {
        Ok(tunnel) => {
            socks5_reply(&mut client, 0x00).await?;
            pump(client, tunnel, Vec::new()).await
        }
        Err(e) => {
            socks5_reply(&mut client, 0x05).await?;
            Err(anyhow!("connect {dst} failed: {e}"))
        }
    }
}

async fn socks5_reply(client: &mut TcpStream, rep: u8) -> Result<()> {
    let mut buf = vec![0x05, rep, 0x00, 0x01];
    buf.extend_from_slice(&Ipv4Addr::UNSPECIFIED.octets());
    buf.extend_from_slice(&[0u8, 0u8]);
    client.write_all(&buf).await?;
    Ok(())
}

// ----------------------------------------------------------------------------
// SOCKS4 / SOCKS4a
// ----------------------------------------------------------------------------

async fn handle_socks4(mut client: TcpStream, netstack: NetStack) -> Result<()> {
    // Version byte (0x04) already consumed. Next: CMD, PORT(2), IP(4), USERID\0
    let cmd = client.read_u8().await?;
    let port = client.read_u16().await?;
    let mut ip = [0u8; 4];
    client.read_exact(&mut ip).await?;
    // userid (null-terminated)
    read_until_nul(&mut client).await?;

    if cmd != 0x01 {
        socks4_reply(&mut client, 0x5b).await?;
        return Err(anyhow!("unsupported SOCKS4 command {cmd}"));
    }

    // SOCKS4a: 0.0.0.x means a hostname follows (also null-terminated).
    let dst = if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 {
        let host = read_until_nul(&mut client).await?;
        match resolve_target(&netstack, &host, port).await {
            Ok(d) => d,
            Err(e) => {
                socks4_reply(&mut client, 0x5b).await?;
                return Err(e);
            }
        }
    } else {
        SocketAddr::new(IpAddr::V4(ip.into()), port)
    };

    match netstack.connect(dst).await {
        Ok(tunnel) => {
            socks4_reply(&mut client, 0x5a).await?; // granted
            pump(client, tunnel, Vec::new()).await
        }
        Err(e) => {
            socks4_reply(&mut client, 0x5b).await?; // rejected
            Err(anyhow!("connect {dst} failed: {e}"))
        }
    }
}

async fn socks4_reply(client: &mut TcpStream, code: u8) -> Result<()> {
    // VN=0, CD=code, DSTPORT(2)=0, DSTIP(4)=0
    client.write_all(&[0x00, code, 0, 0, 0, 0, 0, 0]).await?;
    Ok(())
}

async fn read_until_nul(client: &mut TcpStream) -> Result<String> {
    let mut out = Vec::new();
    loop {
        let b = client.read_u8().await?;
        if b == 0 {
            break;
        }
        out.push(b);
        if out.len() > 4096 {
            return Err(anyhow!("socks4 field too long"));
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

// ----------------------------------------------------------------------------
// Bidirectional pump
// ----------------------------------------------------------------------------

/// Copy bytes in both directions between `client` and the tunnel connection.
/// `initial_to_tunnel` is sent to the tunnel first (e.g. buffered HTTP body).
async fn pump(client: TcpStream, mut tunnel: TunnelTcp, initial_to_tunnel: Vec<u8>) -> Result<()> {
    let (mut crd, mut cwr) = client.into_split();
    let writer = tunnel.writer();

    if !initial_to_tunnel.is_empty() {
        let _ = writer.write(initial_to_tunnel);
    }

    // client -> tunnel
    let mut up = tokio::spawn(async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match crd.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if writer.write(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        writer.shutdown();
    });

    // tunnel -> client
    while let Some(data) = tunnel.recv().await {
        if cwr.write_all(&data).await.is_err() {
            break;
        }
    }
    let _ = cwr.shutdown().await;

    // The remote may have half-closed while the client is still uploading; let that
    // direction finish instead of truncating it. The client sees EOF above and should
    // close promptly; bound the wait so a stuck peer cannot pin resources forever.
    match tokio::time::timeout(std::time::Duration::from_secs(30), &mut up).await {
        Ok(_) => {}
        Err(_) => up.abort(),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_authority_forms() {
        assert_eq!(
            parse_authority("example.com", 443).unwrap(),
            ("example.com".to_string(), 443)
        );
        assert_eq!(
            parse_authority("example.com:8080", 443).unwrap(),
            ("example.com".to_string(), 8080)
        );
        assert_eq!(
            parse_authority("[2606:4700::1]:8443", 443).unwrap(),
            ("2606:4700::1".to_string(), 8443)
        );
        assert_eq!(
            parse_authority("[2606:4700::1]", 443).unwrap(),
            ("2606:4700::1".to_string(), 443)
        );
    }

    #[test]
    fn parses_plain_http_urls() {
        assert_eq!(
            parse_http_url("http://example.com/a?b=1").unwrap(),
            ("example.com".to_string(), 80, "/a?b=1".to_string())
        );
        assert_eq!(
            parse_http_url("http://example.com:8080").unwrap(),
            ("example.com".to_string(), 8080, "/".to_string())
        );
        // https belongs on the CONNECT path; never fetched in cleartext.
        assert!(parse_http_url("https://example.com/").is_err());
        assert!(parse_http_url("example.com/").is_err());
    }

    #[test]
    fn finds_header_terminator() {
        assert_eq!(find_subsequence(b"abc\r\n\r\ndef", b"\r\n\r\n"), Some(3));
        assert_eq!(find_subsequence(b"abcdef", b"\r\n\r\n"), None);
    }
}
