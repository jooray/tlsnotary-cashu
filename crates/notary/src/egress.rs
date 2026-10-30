//! Outbound connections: the public internet on port 443, never us.
//!
//! This is the first of three layers (code, systemd `IPAddressDeny=`,
//! nftables; see DESIGN.md §6). Every connection the notary opens on behalf of
//! a prover goes through [`Egress::connect`].

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use hickory_resolver::{
    Resolver, TokioResolver,
    config::{NameServerConfig, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
};
use ipnet::IpNet;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

use crate::config::EgressConfig;

pub const PORT: u16 = 443;

#[derive(Debug, thiserror::Error)]
pub enum EgressError {
    #[error("`{0}` is not a valid DNS host name")]
    BadHost(String),
    #[error("`{host}` resolves to {ip}, which the notary does not connect to")]
    Forbidden { host: String, ip: IpAddr },
    #[error("`{0}` does not resolve")]
    NoAddress(String),
    #[error("too many sessions to `{0}` this hour")]
    RateLimited(String),
    #[error("connecting to `{host}`: {err}")]
    Connect { host: String, err: String },
}

/// Whether `ip` is a globally routable unicast address. Written out instead
/// of relying on `IpAddr::is_global` (unstable) so the policy is visible.
pub fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_global_v4(v4),
        IpAddr::V6(v6) => {
            // IPv4-mapped / compatible addresses would let an AAAA record
            // smuggle an IPv4 target past the v6 rules.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_global_v4(v4);
            }
            is_global_v6(v6)
        }
    }
}

fn in_net(ip: IpAddr, net: &str) -> bool {
    net.parse::<IpNet>().is_ok_and(|n| n.contains(&ip))
}

fn is_global_v4(ip: Ipv4Addr) -> bool {
    const DENY: [&str; 15] = [
        "0.0.0.0/8",          // "this network"
        "10.0.0.0/8",         // RFC 1918
        "100.64.0.0/10",      // CGNAT
        "127.0.0.0/8",        // loopback
        "169.254.0.0/16",     // link-local
        "172.16.0.0/12",      // RFC 1918
        "192.0.0.0/24",       // IETF protocol assignments
        "192.0.2.0/24",       // TEST-NET-1
        "192.88.99.0/24",     // 6to4 relay anycast
        "192.168.0.0/16",     // RFC 1918
        "198.18.0.0/15",      // benchmarking
        "198.51.100.0/24",    // TEST-NET-2
        "203.0.113.0/24",     // TEST-NET-3
        "224.0.0.0/4",        // multicast
        "240.0.0.0/4",        // reserved + broadcast
    ];
    !DENY.iter().any(|n| in_net(IpAddr::V4(ip), n))
}

fn is_global_v6(ip: Ipv6Addr) -> bool {
    // Only 2000::/3 is global unicast; everything else (loopback, ULA,
    // link-local, multicast, NAT64 64:ff9b::/96, discard) is outside it.
    if !in_net(IpAddr::V6(ip), "2000::/3") {
        return false;
    }
    const DENY: [&str; 4] = [
        "2001::/32",     // Teredo: tunnels to arbitrary IPv4
        "2001:db8::/32", // documentation
        "2002::/16",     // 6to4: embeds an arbitrary IPv4
        "2001:10::/28",  // ORCHID
    ];
    !DENY.iter().any(|n| in_net(IpAddr::V6(ip), n))
}

/// A DNS host name as accepted for targets: letters, digits, hyphens, dots,
/// at least one dot, no IP literal, no port.
pub fn valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || host.parse::<IpAddr>().is_ok() {
        return false;
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    let labels: Vec<&str> = host.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        // A purely numeric last label is not a TLD (blocks `1.2.3.4.` tricks).
        && !labels.last().unwrap().bytes().all(|b| b.is_ascii_digit())
}

pub struct Egress {
    resolver: TokioResolver,
    deny: Vec<IpNet>,
    per_host_per_hour: u32,
    connect_timeout: Duration,
    recent: Mutex<HashMap<String, Vec<Instant>>>,
}

impl Egress {
    pub fn new(config: &EgressConfig) -> anyhow::Result<Self> {
        let servers = config
            .resolvers
            .iter()
            .map(|ip| NameServerConfig::udp_and_tcp(*ip))
            .collect();
        let resolver = Resolver::builder_with_config(
            ResolverConfig::from_name_servers(servers),
            TokioRuntimeProvider::default(),
        )
        .build()?;
        Ok(Self {
            resolver,
            deny: config.deny.clone(),
            per_host_per_hour: config.per_host_per_hour,
            connect_timeout: Duration::from_secs(config.connect_timeout_secs),
            recent: Mutex::new(HashMap::new()),
        })
    }

    pub fn allowed(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        is_global(ip) && !self.deny.iter().any(|n| n.contains(&ip))
    }

    /// Resolves `host` and returns the address to connect to. If any
    /// resolved address is forbidden the host is rejected outright, so a
    /// mixed answer cannot be used to probe us.
    pub async fn resolve(&self, host: &str) -> Result<SocketAddr, EgressError> {
        if !valid_host(host) {
            return Err(EgressError::BadHost(host.to_string()));
        }
        let fqdn = format!("{}.", host.trim_end_matches('.'));
        let lookup = self
            .resolver
            .lookup_ip(fqdn.as_str())
            .await
            .map_err(|_| EgressError::NoAddress(host.to_string()))?;
        let ips: Vec<IpAddr> = lookup.iter().collect();
        if ips.is_empty() {
            return Err(EgressError::NoAddress(host.to_string()));
        }
        if let Some(bad) = ips.iter().find(|ip| !self.allowed(**ip)) {
            return Err(EgressError::Forbidden {
                host: host.to_string(),
                ip: *bad,
            });
        }
        // Prefer IPv4: jl has no global IPv6 address.
        let ip = ips.iter().find(|ip| ip.is_ipv4()).unwrap_or(&ips[0]);
        Ok(SocketAddr::new(*ip, PORT))
    }

    fn take_rate_slot(&self, host: &str) -> Result<(), EgressError> {
        let mut recent = self.recent.lock().unwrap();
        let now = Instant::now();
        let hour = Duration::from_secs(3600);
        recent.retain(|_, v| {
            v.retain(|t| now.duration_since(*t) < hour);
            !v.is_empty()
        });
        let entry = recent.entry(host.to_ascii_lowercase()).or_default();
        if entry.len() as u32 >= self.per_host_per_hour {
            return Err(EgressError::RateLimited(host.to_string()));
        }
        entry.push(now);
        Ok(())
    }

    /// Opens a TCP connection to `host:443` if the policy allows it.
    pub async fn connect(&self, host: &str) -> Result<TcpStream, EgressError> {
        let addr = self.resolve(host).await?;
        self.take_rate_slot(host)?;
        let stream = tokio::time::timeout(self.connect_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| EgressError::Connect {
                host: host.to_string(),
                err: "timed out".into(),
            })?
            .map_err(|e| EgressError::Connect {
                host: host.to_string(),
                err: e.to_string(),
            })?;
        // Re-check what we actually connected to.
        let peer = stream.peer_addr().map_err(|e| EgressError::Connect {
            host: host.to_string(),
            err: e.to_string(),
        })?;
        if !self.allowed(peer.ip()) || peer.port() != PORT {
            return Err(EgressError::Forbidden {
                host: host.to_string(),
                ip: peer.ip(),
            });
        }
        let _ = stream.set_nodelay(true);
        Ok(stream)
    }
}

/// A stream that fails once more than `max_up` bytes were written or
/// `max_down` bytes were read. Keeps notary egress to what was paid for.
pub struct Capped<S> {
    inner: S,
    up: usize,
    down: usize,
    max_up: usize,
    max_down: usize,
}

impl<S> Capped<S> {
    pub fn new(inner: S, max_up: usize, max_down: usize) -> Self {
        Self {
            inner,
            up: 0,
            down: 0,
            max_up,
            max_down,
        }
    }
}

fn over_cap(what: &str) -> std::io::Error {
    std::io::Error::other(format!("{what} byte cap exceeded"))
}

impl<S: AsyncRead + Unpin> AsyncRead for Capped<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = res {
            self.down += buf.filled().len() - before;
            if self.down > self.max_down {
                return Poll::Ready(Err(over_cap("download")));
            }
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Capped<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        if self.up + buf.len() > self.max_up {
            return Poll::Ready(Err(over_cap("upload")));
        }
        let res = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = res {
            self.up += n;
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn global_policy() {
        for bad in [
            "127.0.0.1", "10.1.2.3", "172.20.0.1", "192.168.1.18", "100.64.1.1", "169.254.169.254",
            "0.0.0.0", "224.0.0.1", "255.255.255.255", "198.18.0.1", "::1", "fe80::1", "fc00::1",
            "fd12::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::1",
            "2001:0:4136:e378::1", "2001:db8::1", "ff02::1", "::",
        ] {
            assert!(!is_global(ip(bad)), "{bad} must not be global");
        }
        for good in ["1.1.1.1", "93.184.215.14", "2606:4700::6810:84e5", "::ffff:1.1.1.1"] {
            assert!(is_global(ip(good)), "{good} must be global");
        }
    }

    #[test]
    fn host_names() {
        for good in ["example.com", "api.x.com", "a-b.example.co.uk", "example.com."] {
            assert!(valid_host(good), "{good}");
        }
        for bad in [
            "", "localhost", "1.2.3.4", "::1", "[::1]", "example.com:22", "-a.com", "a..com",
            "exa mple.com", "1.2.3.4.", "user@example.com", "example.com/x",
        ] {
            assert!(!valid_host(bad), "{bad}");
        }
    }

    #[tokio::test]
    async fn deny_list_and_rate_limit() {
        let e = Egress::new(&EgressConfig {
            resolvers: vec![ip("1.1.1.1")],
            deny: vec!["45.10.20.8/29".parse().unwrap()],
            per_host_per_hour: 2,
            connect_timeout_secs: 5,
        })
        .unwrap();
        assert!(!e.allowed(ip("45.10.20.9")));
        assert!(!e.allowed(ip("::ffff:45.10.20.12")));
        assert!(e.allowed(ip("45.10.20.16")));
        assert!(e.take_rate_slot("Example.com").is_ok());
        assert!(e.take_rate_slot("example.com").is_ok());
        assert!(e.take_rate_slot("example.com").is_err());
        assert!(e.take_rate_slot("other.com").is_ok());
    }
}
