//! Which client a request belongs to, for the per-client rate limit
//! (audit round 7, M7-5).
//!
//! The limiter used to key on the TCP peer (`enforce_by_peer`, the H-7 fix). In
//! every shipped topology that peer is the frontend nginx — production is
//! Caddy -> nginx -> API — so all users shared ONE bucket and about 30 rps from
//! a single client put everyone on 429 (quotes null, bridging stopped).
//!
//! The fix keeps the peer as the key unless the peer is a proxy the operator
//! has declared trusted (`--trusted-proxy CIDR`, repeatable / comma-separated).
//! Only then is `X-Forwarded-For` consulted, and only its rightmost hop that is
//! NOT itself a trusted proxy is used: everything to the left of that hop was
//! written by a party we do not trust and may be invented. With no trusted
//! proxies configured (the default) the behaviour is exactly the old one, so a
//! deployment that publishes the API directly cannot be bypassed by a client
//! that rotates a fake `X-Forwarded-For` per request.

use std::net::{IpAddr, SocketAddr};

use axum::extract::connect_info::ConnectInfo;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use bridge_core::ratelimit::RateLimit;

/// One `addr/prefix` network. A bare address is a /32 (or /128).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> anyhow::Result<Cidr> {
        let s = s.trim();
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let net: IpAddr = addr
            .parse()
            .map_err(|_| anyhow::anyhow!("--trusted-proxy: `{s}` is not an IP or CIDR"))?;
        let net = canonical(net);
        let max = if net.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| anyhow::anyhow!("--trusted-proxy: bad prefix in `{s}`"))?,
            None => max,
        };
        Ok(Cidr { net, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, canonical(ip)) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = if self.prefix == 0 { 0 } else { u32::MAX << (32 - self.prefix) };
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = if self.prefix == 0 { 0 } else { u128::MAX << (128 - self.prefix) };
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }
}

/// An IPv4-mapped IPv6 peer (`::ffff:10.0.0.2`, what a dual-stack listener
/// reports) is the IPv4 address, for matching and for bucketing alike.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// The proxies whose forwarding headers are believed. Empty = believe none.
#[derive(Clone, Debug, Default)]
pub struct TrustedProxies(Vec<Cidr>);

impl TrustedProxies {
    /// From the `--trusted-proxy` values; each may itself be comma-separated.
    pub fn parse<S: AsRef<str>>(specs: &[S]) -> anyhow::Result<TrustedProxies> {
        let mut out = Vec::new();
        for spec in specs {
            for part in spec.as_ref().split(',').map(str::trim).filter(|p| !p.is_empty()) {
                out.push(Cidr::parse(part)?);
            }
        }
        Ok(TrustedProxies(out))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|c| c.contains(ip))
    }
}

/// One `X-Forwarded-For` element as an address: `1.2.3.4`, `1.2.3.4:5678`,
/// `2001:db8::1` or `[2001:db8::1]:5678`.
fn parse_hop(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(canonical(ip));
    }
    s.parse::<SocketAddr>().ok().map(|a| canonical(a.ip()))
}

/// The bucket key for a request that arrived from `peer` with `headers`.
///
/// * peer unknown            -> `""` (one shared bucket: a bound, not a bypass)
/// * peer not trusted        -> the peer, whatever the headers claim
/// * peer trusted            -> walk `X-Forwarded-For` right to left and take the
///   first hop that is not a trusted proxy; an unparseable hop stops the walk at
///   the last trusted address (fail toward a SHARED bucket, never a fresh one).
///   No `X-Forwarded-For` at all falls back to `X-Real-IP`, then to the peer.
pub fn client_key(peer: Option<IpAddr>, headers: &HeaderMap, trusted: &TrustedProxies) -> String {
    let Some(peer) = peer.map(canonical) else { return String::new() };
    if !trusted.contains(peer) {
        return peer.to_string();
    }

    let hops: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .collect();

    if hops.is_empty() {
        let real = headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(parse_hop);
        return real.unwrap_or(peer).to_string();
    }

    let mut last_trusted = peer;
    for hop in hops.iter().rev() {
        match parse_hop(hop) {
            Some(ip) if trusted.contains(ip) => last_trusted = ip,
            Some(ip) => return ip.to_string(),
            None => break,
        }
    }
    last_trusted.to_string()
}

/// The limiter plus who may speak for a client.
#[derive(Clone)]
pub struct ClientLimit {
    pub limit: RateLimit,
    pub trusted: TrustedProxies,
}

/// Middleware enforcing [`ClientLimit`] keyed on [`client_key`]. Needs the
/// server built with `into_make_service_with_connect_info::<SocketAddr>()`.
pub async fn enforce_by_client(
    State(cl): State<ClientLimit>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|ConnectInfo(a)| a.ip());
    let key = client_key(peer, req.headers(), &cl.trusted);
    if cl.limit.check(&key) {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::TOO_MANY_REQUESTS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::middleware;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn xff(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", v.parse().unwrap());
        h
    }

    #[test]
    fn cidr_parsing_and_matching() {
        let c = Cidr::parse("172.30.88.0/24").unwrap();
        assert!(c.contains(ip("172.30.88.7")));
        assert!(!c.contains(ip("172.30.89.7")));
        assert!(c.contains(ip("::ffff:172.30.88.7")), "v4-mapped peer is the v4 address");
        assert!(Cidr::parse("10.0.0.1").unwrap().contains(ip("10.0.0.1")));
        assert!(!Cidr::parse("10.0.0.1").unwrap().contains(ip("10.0.0.2")));
        assert!(Cidr::parse("fd00::/8").unwrap().contains(ip("fd12::1")));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")));
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("nginx").is_err());
        let t = TrustedProxies::parse(&["10.0.0.0/8, 192.168.0.0/16", ""]).unwrap();
        assert!(t.contains(ip("192.168.1.1")) && t.contains(ip("10.1.1.1")));
    }

    #[test]
    fn no_trusted_proxies_keys_on_the_peer_regardless_of_headers() {
        let t = TrustedProxies::default();
        assert_eq!(client_key(Some(ip("10.0.0.5")), &xff("1.2.3.4"), &t), "10.0.0.5");
        assert_eq!(client_key(None, &xff("1.2.3.4"), &t), "");
    }

    #[test]
    fn spoofed_xff_from_an_untrusted_peer_is_ignored() {
        let t = TrustedProxies::parse(&["172.30.88.0/24"]).unwrap();
        assert_eq!(client_key(Some(ip("203.0.113.9")), &xff("1.2.3.4"), &t), "203.0.113.9");
    }

    #[test]
    fn trusted_peer_yields_the_rightmost_untrusted_hop() {
        let t = TrustedProxies::parse(&["172.30.88.0/24"]).unwrap();
        // Client invented "6.6.6.6"; Caddy appended the real 198.51.100.4;
        // nginx (another trusted hop) appended Caddy.
        let h = xff("6.6.6.6, 198.51.100.4, 172.30.88.3");
        assert_eq!(client_key(Some(ip("172.30.88.2")), &h, &t), "198.51.100.4");
        // Port and bracket forms.
        assert_eq!(client_key(Some(ip("172.30.88.2")), &xff("[2001:db8::1]:443"), &t), "2001:db8::1");
        assert_eq!(client_key(Some(ip("172.30.88.2")), &xff("198.51.100.4:1"), &t), "198.51.100.4");
        // Garbage stops the walk at the last trusted hop (shared, never fresh).
        assert_eq!(client_key(Some(ip("172.30.88.2")), &xff("junk"), &t), "172.30.88.2");
        assert_eq!(
            client_key(Some(ip("172.30.88.2")), &xff("1.1.1.1, junk, 172.30.88.3"), &t),
            "172.30.88.3"
        );
        // No XFF: X-Real-IP, then the peer.
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", "198.51.100.7".parse().unwrap());
        assert_eq!(client_key(Some(ip("172.30.88.2")), &h, &t), "198.51.100.7");
        assert_eq!(client_key(Some(ip("172.30.88.2")), &HeaderMap::new(), &t), "172.30.88.2");
    }

    /// End to end through the real middleware: a burst-1 limiter.
    fn app(trusted: &[&str]) -> Router {
        let cl = ClientLimit {
            limit: RateLimit::new(1, 0.0001),
            trusted: TrustedProxies::parse(trusted).unwrap(),
        };
        Router::new()
            .route("/graphql", get(|| async { "ok" }))
            .route_layer(middleware::from_fn_with_state(cl, enforce_by_client))
    }

    async fn status(app: &Router, peer: &str, xff: Option<&str>) -> StatusCode {
        let mut req = Request::builder().uri("/graphql");
        if let Some(v) = xff {
            req = req.header("x-forwarded-for", v);
        }
        let mut req = req.body(Body::empty()).unwrap();
        let addr: SocketAddr = format!("{peer}:4000").parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));
        app.clone().oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn untrusted_peer_cannot_escape_its_bucket_by_rotating_xff() {
        let app = app(&["172.30.88.0/24"]);
        assert_eq!(status(&app, "203.0.113.9", Some("1.1.1.1")).await, StatusCode::OK);
        assert_eq!(
            status(&app, "203.0.113.9", Some("2.2.2.2")).await,
            StatusCode::TOO_MANY_REQUESTS,
            "a fresh spoofed XFF must not buy a fresh bucket"
        );
    }

    #[tokio::test]
    async fn clients_behind_a_trusted_proxy_get_their_own_buckets() {
        let app = app(&["172.30.88.0/24"]);
        let nginx = "172.30.88.2";
        assert_eq!(status(&app, nginx, Some("198.51.100.4")).await, StatusCode::OK);
        assert_eq!(
            status(&app, nginx, Some("198.51.100.4")).await,
            StatusCode::TOO_MANY_REQUESTS,
            "premise: that client is exhausted"
        );
        assert_eq!(
            status(&app, nginx, Some("198.51.100.5")).await,
            StatusCode::OK,
            "another client through the same proxy is unaffected (M7-5)"
        );
    }

    #[tokio::test]
    async fn without_trust_the_proxy_is_still_one_bucket() {
        // Default: today's behaviour, unchanged.
        let app = app(&[]);
        assert_eq!(status(&app, "172.30.88.2", Some("198.51.100.4")).await, StatusCode::OK);
        assert_eq!(
            status(&app, "172.30.88.2", Some("198.51.100.5")).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }
}
