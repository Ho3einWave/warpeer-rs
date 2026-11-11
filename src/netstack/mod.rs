//! Userspace TCP/IP stack built on smoltcp.
//!
//! The WireGuard engine and this netstack exchange raw IP packets over two
//! channels (see [`EngineIo`]). On top of that we run a single-threaded smoltcp
//! `Interface` poll loop in a dedicated tokio task, and expose an async API:
//!   * [`NetStack::connect`]  — open a TCP connection through the tunnel,
//!   * [`NetStack::resolve`]  — resolve a hostname via DNS through the tunnel.
//!
//! Each TCP connection is represented to callers by a [`TunnelTcp`]: bytes written
//! with `write` are injected into the smoltcp socket's tx buffer, and bytes received
//! are delivered on its `recv` channel.

mod device;

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Weak};
use std::time::Duration;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{dns, tcp};
use smoltcp::time::Instant;
use smoltcp::wire::{DnsQueryType, HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv6Address};
use tokio::sync::{mpsc, oneshot};

use device::ChannelDevice;

/// Per-direction TCP socket buffer bounds the advertised receive window: at
/// ~100 ms RTT, 256 KiB caps a flow at ~2.5 MB/s, while 2 MiB keeps it open for
/// ~20 MB/s. Configurable from the CLI (`--tcp-buf`); the value is per direction.
pub const DEFAULT_TCP_BUF: usize = 2 * 1024 * 1024;
const CONNECT_TIMEOUT: smoltcp::time::Duration = smoltcp::time::Duration::from_secs(12);
const DNS_TIMEOUT: smoltcp::time::Duration = smoltcp::time::Duration::from_secs(8);

/// Channels the WireGuard engine uses to exchange IP packets with the netstack.
pub struct EngineIo {
    /// Inject a received (decapsulated) IP packet into the netstack.
    pub inbound_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// IP packets the netstack wants sent out (to be encapsulated by the engine).
    pub outbound_rx: mpsc::UnboundedReceiver<Vec<u8>>,
}

/// Handle for opening connections / resolving names through the tunnel.
#[derive(Clone)]
pub struct NetStack {
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    /// Dropped when the last `NetStack` handle goes away; the poll task watches it
    /// through a `Weak` so it does not outlive its owner (e.g. a failed tunnel
    /// attempt that is retried with different obfuscation settings).
    _lifetime: Arc<()>,
}

enum Cmd {
    Connect {
        dst: SocketAddr,
        reply: oneshot::Sender<io::Result<TunnelTcp>>,
    },
    Resolve {
        name: String,
        reply: oneshot::Sender<io::Result<Vec<IpAddr>>>,
    },
    Write {
        id: u64,
        data: Vec<u8>,
    },
    Shutdown {
        id: u64,
    },
}

/// A TCP connection living inside the netstack.
pub struct TunnelTcp {
    id: u64,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    recv_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    shutdown_sent: bool,
}

impl TunnelTcp {
    /// Queue `data` to be sent over the connection.
    pub fn write(&self, data: Vec<u8>) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        self.cmd_tx
            .send(Cmd::Write { id: self.id, data })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "netstack closed"))
    }

    /// Receive the next chunk of bytes, or `None` at EOF.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.recv_rx.recv().await
    }

    /// Half-close the send side (sends FIN).
    pub fn shutdown(&mut self) {
        if !self.shutdown_sent {
            let _ = self.cmd_tx.send(Cmd::Shutdown { id: self.id });
            self.shutdown_sent = true;
        }
    }

    /// A cheap, cloneable handle for the send side, so reading and writing can be
    /// driven from independent tasks.
    pub fn writer(&self) -> TunnelWriter {
        TunnelWriter {
            id: self.id,
            cmd_tx: self.cmd_tx.clone(),
        }
    }
}

/// Write half of a [`TunnelTcp`].
#[derive(Clone)]
pub struct TunnelWriter {
    id: u64,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
}

impl TunnelWriter {
    pub fn write(&self, data: Vec<u8>) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        self.cmd_tx
            .send(Cmd::Write { id: self.id, data })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "netstack closed"))
    }

    pub fn shutdown(&self) {
        let _ = self.cmd_tx.send(Cmd::Shutdown { id: self.id });
    }
}

impl Drop for TunnelTcp {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl NetStack {
    /// Create the netstack, spawning its poll loop. Returns the caller handle plus
    /// the [`EngineIo`] channels for the WireGuard engine.
    pub fn new(
        addresses: Vec<IpAddr>,
        dns_servers: Vec<IpAddr>,
        mtu: usize,
        sock_buf: usize,
    ) -> (NetStack, EngineIo) {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<Cmd>();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        let lifetime = Arc::new(());
        let task = NetStackTask::new(
            addresses,
            dns_servers,
            mtu,
            sock_buf,
            outbound_tx,
            cmd_tx.clone(),
            cmd_rx,
            inbound_rx,
            Arc::downgrade(&lifetime),
        );
        tokio::spawn(task.run());

        (
            NetStack {
                cmd_tx,
                _lifetime: lifetime,
            },
            EngineIo {
                inbound_tx,
                outbound_rx,
            },
        )
    }

    /// Open a TCP connection to `dst` through the tunnel.
    pub async fn connect(&self, dst: SocketAddr) -> io::Result<TunnelTcp> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(Cmd::Connect { dst, reply })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "netstack closed"))?;
        rx.await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "netstack dropped"))?
    }

    /// Resolve a hostname (A records) through the tunnel.
    pub async fn resolve(&self, name: &str) -> io::Result<Vec<IpAddr>> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(Cmd::Resolve {
                name: name.to_string(),
                reply,
            })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "netstack closed"))?;
        rx.await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "netstack dropped"))?
    }
}

struct Conn {
    handle: SocketHandle,
    out_buf: std::collections::VecDeque<u8>,
    /// `Some` until the remote half closes; dropping it yields EOF to the app.
    from_remote_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    pending: Option<PendingConnect>,
    app_closed: bool,
    closed_issued: bool,
    deadline: Instant,
}

struct PendingConnect {
    reply: oneshot::Sender<io::Result<TunnelTcp>>,
    tcp: TunnelTcp,
}

struct PendingDns {
    query: dns::QueryHandle,
    reply: oneshot::Sender<io::Result<Vec<IpAddr>>>,
    deadline: Instant,
}

/// A resolve request waiting for a free DNS query slot.
struct PendingResolve {
    name: String,
    reply: oneshot::Sender<io::Result<Vec<IpAddr>>>,
    deadline: Instant,
}

struct NetStackTask {
    iface: Interface,
    device: ChannelDevice,
    sockets: SocketSet<'static>,
    dns_handle: SocketHandle,
    /// Per-direction TCP buffer size for each connection.
    sock_buf: usize,
    conns: HashMap<u64, Conn>,
    pending_dns: Vec<PendingDns>,
    pending_resolve: Vec<PendingResolve>,
    next_id: u64,
    cmd_self: mpsc::UnboundedSender<Cmd>,
    cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    inbound_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    lifetime: Weak<()>,
}

impl NetStackTask {
    // The constructor wires up every channel the poll task owns; grouping them into
    // a struct would not make the call site clearer.
    #[allow(clippy::too_many_arguments)]
    fn new(
        addresses: Vec<IpAddr>,
        dns_servers: Vec<IpAddr>,
        mtu: usize,
        sock_buf: usize,
        outbound_tx: mpsc::UnboundedSender<Vec<u8>>,
        cmd_self: mpsc::UnboundedSender<Cmd>,
        cmd_rx: mpsc::UnboundedReceiver<Cmd>,
        inbound_rx: mpsc::UnboundedReceiver<Vec<u8>>,
        lifetime: Weak<()>,
    ) -> Self {
        let mut device = ChannelDevice::new(outbound_tx, mtu);

        let config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut device, Instant::now());

        let mut has_v4 = false;
        let mut has_v6 = false;
        iface.update_ip_addrs(|addrs| {
            for ip in &addresses {
                let (cidr, v4) = match ip {
                    IpAddr::V4(a) => (IpCidr::new(IpAddress::Ipv4(*a), 32), true),
                    IpAddr::V6(a) => (IpCidr::new(IpAddress::Ipv6(*a), 128), false),
                };
                if addrs.push(cidr).is_ok() {
                    if v4 {
                        has_v4 = true;
                    } else {
                        has_v6 = true;
                    }
                }
            }
        });

        // Default routes so off-link destinations are emitted out the interface.
        // In medium=ip there is no L2 next-hop resolution, so the gateway value is
        // only used to select the route; the emitted packet carries the real dst.
        if has_v4 {
            let _ = iface
                .routes_mut()
                .add_default_ipv4_route(Ipv4Address::new(10, 255, 255, 254));
        }
        if has_v6 {
            let _ = iface
                .routes_mut()
                .add_default_ipv6_route(Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        }

        // DNS socket pointed at the tunnel's resolver(s).
        let servers: Vec<IpAddress> = dns_servers.iter().map(|ip| IpAddress::from(*ip)).collect();
        // Browsers fire many DNS lookups in parallel on page load; give the resolver
        // plenty of concurrent query slots (overflow is queued, see `pending_resolve`).
        let queries: Vec<Option<dns::DnsQuery>> = (0..64).map(|_| None).collect();
        let dns_socket = dns::Socket::new(&servers, queries);

        let mut sockets = SocketSet::new(Vec::new());
        let dns_handle = sockets.add(dns_socket);

        NetStackTask {
            iface,
            device,
            sockets,
            dns_handle,
            sock_buf,
            conns: HashMap::new(),
            pending_dns: Vec::new(),
            pending_resolve: Vec::new(),
            next_id: 1,
            cmd_self,
            cmd_rx,
            inbound_rx,
            lifetime,
        }
    }

    async fn run(mut self) {
        loop {
            // The owning `NetStack` handle(s) are gone: nothing can use this stack anymore.
            if self.lifetime.upgrade().is_none() {
                return;
            }

            // Move any received packets into the device before polling.
            while let Ok(pkt) = self.inbound_rx.try_recv() {
                self.device.push_rx(pkt);
            }

            let now = Instant::now();
            self.iface.poll(now, &mut self.device, &mut self.sockets);
            self.process_conns(now);
            self.pump_resolves(now);
            self.process_dns(now);
            // Poll again so freshly-queued egress data leaves promptly.
            self.iface.poll(now, &mut self.device, &mut self.sockets);

            let delay = self
                .iface
                .poll_delay(now, &self.sockets)
                .map(|d| Duration::from_millis(d.total_millis().min(1000)))
                .unwrap_or(Duration::from_millis(200));

            tokio::select! {
                biased;
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(cmd) => self.handle_cmd(cmd, now),
                        None => return, // all handles dropped
                    }
                }
                pkt = self.inbound_rx.recv() => {
                    match pkt {
                        Some(pkt) => self.device.push_rx(pkt),
                        // The engine is gone; without it no packet can ever arrive again.
                        // Returning (instead of looping on `None`) avoids busy-spinning.
                        None => return,
                    }
                }
                _ = tokio::time::sleep(delay) => {}
            }
        }
    }

    fn handle_cmd(&mut self, cmd: Cmd, now: Instant) {
        match cmd {
            Cmd::Connect { dst, reply } => self.do_connect(dst, reply, now),
            Cmd::Resolve { name, reply } => self.do_resolve(&name, reply, now),
            Cmd::Write { id, data } => {
                if let Some(conn) = self.conns.get_mut(&id) {
                    conn.out_buf.extend(data);
                }
            }
            Cmd::Shutdown { id } => {
                if let Some(conn) = self.conns.get_mut(&id) {
                    conn.app_closed = true;
                }
            }
        }
    }

    fn do_connect(
        &mut self,
        dst: SocketAddr,
        reply: oneshot::Sender<io::Result<TunnelTcp>>,
        now: Instant,
    ) {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; self.sock_buf]),
            tcp::SocketBuffer::new(vec![0u8; self.sock_buf]),
        );
        // A proxy forwards interactive request/response traffic; Nagle would add
        // up to 10 ms per small write (smoltcp's delayed-ACK interval).
        socket.set_nagle_enabled(false);

        let local_port = ephemeral_port();
        let remote = (IpAddress::from(dst.ip()), dst.port());
        if let Err(e) = socket.connect(self.iface.context(), remote, local_port) {
            let _ = reply.send(Err(io::Error::other(format!("connect failed: {e:?}"))));
            return;
        }

        let handle = self.sockets.add(socket);
        let id = self.next_id;
        self.next_id += 1;

        let (from_remote_tx, recv_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let tcp = TunnelTcp {
            id,
            cmd_tx: self.cmd_self.clone(),
            recv_rx,
            shutdown_sent: false,
        };

        self.conns.insert(
            id,
            Conn {
                handle,
                out_buf: std::collections::VecDeque::new(),
                from_remote_tx: Some(from_remote_tx),
                pending: Some(PendingConnect { reply, tcp }),
                app_closed: false,
                closed_issued: false,
                deadline: now + CONNECT_TIMEOUT,
            },
        );
    }

    fn do_resolve(
        &mut self,
        name: &str,
        reply: oneshot::Sender<io::Result<Vec<IpAddr>>>,
        now: Instant,
    ) {
        // Queue the request; pump_resolves() starts it once a query slot is free.
        self.pending_resolve.push(PendingResolve {
            name: name.to_string(),
            reply,
            deadline: now + DNS_TIMEOUT,
        });
    }

    /// Start as many queued resolve requests as there are free DNS query slots.
    fn pump_resolves(&mut self, now: Instant) {
        if self.pending_resolve.is_empty() {
            return;
        }
        let dns_socket = self.sockets.get_mut::<dns::Socket>(self.dns_handle);
        let mut still = Vec::new();
        for req in std::mem::take(&mut self.pending_resolve) {
            if now >= req.deadline {
                let _ = req.reply.send(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "dns query timed out (queued)",
                )));
                continue;
            }
            match dns_socket.start_query(self.iface.context(), &req.name, DnsQueryType::A) {
                Ok(query) => self.pending_dns.push(PendingDns {
                    query,
                    reply: req.reply,
                    deadline: req.deadline,
                }),
                Err(dns::StartQueryError::NoFreeSlot) => still.push(req), // retry next poll
                Err(e) => {
                    let _ = req
                        .reply
                        .send(Err(io::Error::other(format!("dns query failed: {e:?}"))));
                }
            }
        }
        self.pending_resolve.extend(still);
    }

    fn process_dns(&mut self, now: Instant) {
        let dns_socket = self.sockets.get_mut::<dns::Socket>(self.dns_handle);
        let mut still = Vec::new();
        for p in std::mem::take(&mut self.pending_dns) {
            match dns_socket.get_query_result(p.query) {
                Ok(addrs) => {
                    let ips: Vec<IpAddr> = addrs.iter().map(|a| IpAddr::from(*a)).collect();
                    let _ = p.reply.send(Ok(ips));
                }
                Err(dns::GetQueryResultError::Pending) => {
                    if now >= p.deadline {
                        dns_socket.cancel_query(p.query);
                        let _ = p.reply.send(Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "dns query timed out",
                        )));
                    } else {
                        still.push(p);
                    }
                }
                Err(_) => {
                    let _ = p.reply.send(Err(io::Error::other("dns query failed")));
                }
            }
        }
        self.pending_dns = still;
    }

    fn process_conns(&mut self, now: Instant) {
        let mut to_remove = Vec::new();
        for (id, conn) in self.conns.iter_mut() {
            let socket = self.sockets.get_mut::<tcp::Socket>(conn.handle);
            let state = socket.state();

            // Resolve a pending connect once the handshake completes or fails.
            if let Some(pc) = conn.pending.take() {
                if state == tcp::State::Established {
                    let _ = pc.reply.send(Ok(pc.tcp));
                } else if state == tcp::State::Closed || now >= conn.deadline {
                    let _ = pc.reply.send(Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "connection failed",
                    )));
                    socket.abort();
                    to_remove.push(*id);
                    continue;
                } else {
                    conn.pending = Some(pc); // still connecting
                    continue;
                }
            }

            // app -> socket
            while socket.can_send() && !conn.out_buf.is_empty() {
                let chunk = conn.out_buf.make_contiguous();
                match socket.send_slice(chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        conn.out_buf.drain(..n);
                    }
                    Err(_) => break,
                }
            }
            if conn.app_closed && conn.out_buf.is_empty() && !conn.closed_issued {
                socket.close();
                conn.closed_issued = true;
            }

            // socket -> app
            if let Some(tx) = &conn.from_remote_tx {
                let mut recv_buf = [0u8; 65536];
                while socket.can_recv() {
                    match socket.recv_slice(&mut recv_buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if tx.send(recv_buf[..n].to_vec()).is_err() {
                                socket.abort();
                                to_remove.push(*id);
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }

            // The remote half closed: drop the sender so the app sees EOF. Keep the
            // socket around while our half is still open, so a half-close (e.g. a
            // server finishing a `Connection: close` response) does not stall the app.
            if !socket.may_recv() {
                conn.from_remote_tx = None;
            }

            // Fully closed: drop the conn (and its from_remote_tx => EOF for the app).
            if !socket.is_active() && state != tcp::State::SynSent {
                to_remove.push(*id);
            }
        }

        for id in to_remove {
            if let Some(conn) = self.conns.remove(&id) {
                self.sockets.remove(conn.handle);
            }
        }
    }
}

fn ephemeral_port() -> u16 {
    use rand::Rng;
    rand::thread_rng().gen_range(1024..=65535)
}
