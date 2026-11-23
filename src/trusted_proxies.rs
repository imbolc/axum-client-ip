//! Trusted proxies and the "rightmost untrusted hop" client IP resolution
use std::{
    error::Error,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

use axum::{
    extract::{ConnectInfo, Extension, FromRequestParts},
    http::{HeaderMap, HeaderName, request::Parts},
};

use crate::Rejection;

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

/// The maximum number of `X-Forwarded-For` entries examined per request
///
/// Entries are examined from the right, so reaching the limit means that this
/// many hops in a row were trusted. The request is rejected then. Real proxy
/// chains are far shorter, so the limit only bounds the work an oversized
/// header can cause.
pub const MAX_FORWARDED_ENTRIES: usize = 32;

/// The longest header entry echoed back in a rejection message
const MAX_ECHOED_LEN: usize = 64;

/// An IP network in CIDR notation, e.g. `10.0.0.0/8` or `2001:db8::/32`
///
/// Parsing accepts an address with or without a prefix length. A bare address
/// is a single-host network (`/32` for IPv4, `/128` for IPv6). Host bits below
/// the prefix are ignored: `10.1.2.3/8` is the same as `10.0.0.0/8`.
///
/// IPv4-mapped IPv6 networks (`::ffff:a.b.c.d/n`, `n >= 96`) are converted to
/// the equivalent IPv4 network. IPv4 and IPv6 are otherwise matched
/// separately, so `::/0` doesn't match IPv4 addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

fn v4_mask(prefix: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
}

fn v6_mask(prefix: u8) -> u128 {
    u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0)
}

impl Cidr {
    /// Returns `true` if the address belongs to the network
    ///
    /// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are matched as IPv4.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = v4_mask(self.prefix);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = v6_mask(self.prefix);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// Invalid [`Cidr`]
#[derive(Debug)]
pub struct ParseCidrError(String);

impl fmt::Display for ParseCidrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Invalid CIDR {:?}. Expected an IP address with an optional prefix length, e.g. `10.0.0.0/8`",
            self.0
        )
    }
}

impl Error for ParseCidrError {}

impl FromStr for Cidr {
    type Err = ParseCidrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || ParseCidrError(s.chars().take(MAX_ECHOED_LEN).collect());
        let (addr, prefix) = match s.trim().split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (s.trim(), None),
        };
        let addr = addr.parse::<IpAddr>().map_err(|_| err())?;
        let prefix = prefix
            .map(|p| {
                // `u8::from_str` alone would also accept a leading `+`
                if p.bytes().all(|b| b.is_ascii_digit()) {
                    p.parse::<u8>().map_err(|_| err())
                } else {
                    Err(err())
                }
            })
            .transpose()?;
        // `::ffff:a.b.c.d/96` and longer is an IPv4 network
        let (addr, offset) = match addr {
            IpAddr::V6(v6) if prefix.is_none_or(|p| p >= 96) => match v6.to_ipv4_mapped() {
                Some(v4) => (IpAddr::V4(v4), 96),
                None => (addr, 0),
            },
            _ => (addr, 0),
        };
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.map_or(max, |p| p - offset);
        if prefix > max {
            return Err(err());
        }
        // Zero the host bits, so equal networks compare equal
        let addr = match addr {
            IpAddr::V4(a) => Ipv4Addr::from(u32::from(a) & v4_mask(prefix)).into(),
            IpAddr::V6(a) => Ipv6Addr::from(u128::from(a) & v6_mask(prefix)).into(),
        };
        Ok(Self { addr, prefix })
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Cidr {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Cidr {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <std::borrow::Cow<'_, str>>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// The networks of proxies you trust to append to `X-Forwarded-For`
///
/// Pass it into the [`axum::routing::Router::layer`] as an extension, next to
/// the [`ClientIpSource::RightmostUntrustedXForwardedFor`] source or for the
/// [`RightmostUntrustedXForwardedFor`] extractor.
///
/// [`FromStr`] parses a comma-separated list, e.g. `127.0.0.0/8, 10.0.0.0/8`.
/// With the `serde` feature it also deserializes from a list of CIDR strings.
///
/// [`ClientIpSource::RightmostUntrustedXForwardedFor`]: crate::ClientIpSource::RightmostUntrustedXForwardedFor
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct TrustedProxies(Vec<Cidr>);

impl TrustedProxies {
    /// Returns `true` if the address belongs to any of the networks
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|net| net.contains(ip))
    }

    /// Wraps [`TrustedProxies`] into the [`axum::extract::Extension`]
    /// for passing to [`axum::routing::Router::layer`]
    pub const fn into_extension(self) -> Extension<Self> {
        Extension(self)
    }
}

impl FromIterator<Cidr> for TrustedProxies {
    fn from_iter<I: IntoIterator<Item = Cidr>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl FromStr for TrustedProxies {
    type Err = ParseCidrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.trim().is_empty() {
            return Ok(Self::default());
        }
        s.split(',').map(str::parse).collect()
    }
}

/// Extracts the client IP by skipping trusted proxies in `X-Forwarded-For`
///
/// The chain is every `X-Forwarded-For` entry in order (multiple headers are
/// joined in header order) followed by the TCP peer address from
/// [`ConnectInfo`]. It is walked from the right and the first entry that
/// isn't in [`TrustedProxies`] is the client. This is the "rightmost trusted
/// range" strategy from
/// [The perils of the "real" client IP][perils] and what nginx's
/// `real_ip_recursive` does.
///
/// - If the peer isn't trusted it is returned and the headers are ignored, so a
///   client connecting directly can't spoof its address.
/// - An entry that isn't a bare IP address (for example one with a port) is
///   rejected when reached, never skipped. Entries to the left of the client
///   aren't looked at.
/// - If every entry is trusted the request is rejected.
/// - At most [`MAX_FORWARDED_ENTRIES`] entries are examined, a longer run of
///   trusted entries is rejected.
/// - IPv4-mapped IPv6 addresses are normalized to IPv4 before matching and in
///   the result.
///
/// Requires a [`TrustedProxies`] extension and
/// `into_make_service_with_connect_info::<SocketAddr>()`, otherwise the
/// request is rejected as a misconfiguration. Also requires the
/// `connect-info` feature.
///
/// ```
/// use axum::{Router, routing::get};
/// use axum_client_ip::{RightmostUntrustedXForwardedFor as ClientIp, TrustedProxies};
///
/// async fn handler(ClientIp(ip): ClientIp) -> String {
///     ip.to_string()
/// }
///
/// // Cloudflare -> Apache on the same host: trust loopback and Cloudflare
/// let trusted: TrustedProxies = "127.0.0.0/8, ::1, 173.245.48.0/20".parse().unwrap();
/// let app: Router = Router::new()
///     .route("/", get(handler))
///     .layer(trusted.into_extension());
/// // Serve with `app.into_make_service_with_connect_info::<std::net::SocketAddr>()`
/// ```
///
/// [perils]: https://adam-p.ca/blog/2022/03/x-forwarded-for/
#[cfg_attr(docsrs, doc(cfg(feature = "connect-info")))]
#[derive(Debug, Clone, Copy)]
pub struct RightmostUntrustedXForwardedFor(pub IpAddr);

impl<S> FromRequestParts<S> for RightmostUntrustedXForwardedFor
where
    S: Sync,
{
    type Rejection = Rejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        ip_from_parts(parts).map(Self)
    }
}

/// Resolves the client IP from the request extensions and headers
pub(crate) fn ip_from_parts(parts: &Parts) -> Result<IpAddr, Rejection> {
    let trusted = parts
        .extensions
        .get::<TrustedProxies>()
        .ok_or(Rejection::NoTrustedProxies)?;
    let ConnectInfo(peer) = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .ok_or(Rejection::NoConnectInfo)?;
    rightmost_untrusted(&parts.headers, peer.ip(), trusted)
}

fn rightmost_untrusted(
    headers: &HeaderMap,
    peer: IpAddr,
    trusted: &TrustedProxies,
) -> Result<IpAddr, Rejection> {
    let peer = peer.to_canonical();
    if !trusted.contains(peer) {
        return Ok(peer);
    }

    let mut examined = 0;
    for value in headers.get_all(X_FORWARDED_FOR).iter().rev() {
        let value = value
            .to_str()
            .map_err(|_| client_ip::Error::NonAsciiHeaderValue {
                header_name: X_FORWARDED_FOR,
            })?;
        for entry in value.rsplit(',') {
            examined += 1;
            if examined > MAX_FORWARDED_ENTRIES {
                return Err(Rejection::TooManyForwardedEntries);
            }
            let entry = entry.trim();
            let ip =
                entry
                    .parse::<IpAddr>()
                    .map_err(|_| client_ip::Error::MalformedHeaderValue {
                        header_name: X_FORWARDED_FOR,
                        header_value: entry.chars().take(MAX_ECHOED_LEN).collect(),
                    })?;
            if !trusted.contains(ip) {
                return Ok(ip.to_canonical());
            }
        }
    }
    Err(Rejection::NoUntrustedClientIp)
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderValue, Request};

    use super::*;

    fn trusted(s: &str) -> TrustedProxies {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn cidr(s: &str) -> Cidr {
        s.parse().unwrap()
    }

    fn resolve(trusted: &TrustedProxies, peer: &str, xff: &[&str]) -> Result<IpAddr, Rejection> {
        let mut headers = HeaderMap::new();
        for value in xff {
            headers.append(X_FORWARDED_FOR, value.parse().unwrap());
        }
        rightmost_untrusted(&headers, ip(peer), trusted)
    }

    fn malformed(entry: &str) -> Rejection {
        client_ip::Error::MalformedHeaderValue {
            header_name: X_FORWARDED_FOR,
            header_value: entry.into(),
        }
        .into()
    }

    #[test]
    fn spoofed_leftmost_entries_are_ignored() {
        let t = trusted("127.0.0.1, 10.0.0.0/8");
        // The client sent `X-Forwarded-For: 6.6.6.6`, Apache appended the real
        // address
        assert_eq!(
            resolve(&t, "127.0.0.1", &["6.6.6.6, 9.9.9.9"]),
            Ok(ip("9.9.9.9"))
        );
        // Spoofed trusted-looking entries on the left don't matter either
        assert_eq!(
            resolve(&t, "127.0.0.1", &["10.0.0.1, 6.6.6.6, 10.0.0.2"]),
            Ok(ip("6.6.6.6"))
        );
    }

    #[test]
    fn untrusted_peer_is_returned_even_with_xff() {
        let t = trusted("127.0.0.1");
        assert_eq!(
            resolve(&t, "8.8.8.8", &["1.1.1.1, 127.0.0.1"]),
            Ok(ip("8.8.8.8"))
        );
        // Not even a malformed header is looked at
        assert_eq!(resolve(&t, "8.8.8.8", &["garbage"]), Ok(ip("8.8.8.8")));
    }

    #[test]
    fn cloudflare_to_apache_chain() {
        // Client -> Cloudflare edge -> Apache (127.0.0.1) -> app
        let t = trusted("127.0.0.1, ::1, 173.245.48.0/20, 2400:cb00::/32");
        assert_eq!(
            resolve(&t, "127.0.0.1", &["203.0.113.7, 173.245.48.9"]),
            Ok(ip("203.0.113.7"))
        );
        assert_eq!(
            resolve(&t, "::1", &["2001:db8::7, 2400:cb00:1::5"]),
            Ok(ip("2001:db8::7"))
        );
        // Without trusting Cloudflare, its edge IP is the client
        assert_eq!(
            resolve(
                &trusted("127.0.0.1"),
                "127.0.0.1",
                &["203.0.113.7, 173.245.48.9"]
            ),
            Ok(ip("173.245.48.9"))
        );
    }

    #[test]
    fn multiple_xff_headers() {
        let t = trusted("10.0.0.0/8, 127.0.0.1");
        assert_eq!(
            resolve(
                &t,
                "127.0.0.1",
                &["6.6.6.6", "5.5.5.5, 10.0.0.1", "10.0.0.2"]
            ),
            Ok(ip("5.5.5.5"))
        );
        // The walk crosses header boundaries
        assert_eq!(
            resolve(&t, "127.0.0.1", &["5.5.5.5", "10.0.0.1, 10.0.0.2"]),
            Ok(ip("5.5.5.5"))
        );
    }

    #[test]
    fn ipv6_and_ipv4_mapped() {
        let t = trusted("::ffff:10.0.0.0/104, 2001:db8::/32, 127.0.0.1");
        // Mapped entries and peers match IPv4 networks, the result is IPv4
        assert_eq!(
            resolve(&t, "::ffff:127.0.0.1", &["::ffff:10.1.2.3, ::ffff:8.8.8.8"]),
            Ok(ip("8.8.8.8"))
        );
        assert_eq!(
            resolve(&t, "127.0.0.1", &["2001:db8::1, ::ffff:10.9.9.9"]),
            Err(Rejection::NoUntrustedClientIp)
        );
        assert_eq!(
            resolve(&t, "127.0.0.1", &["2001:4860::1, 2001:db8::1"]),
            Ok(ip("2001:4860::1"))
        );
        assert_eq!(
            resolve(&trusted("10.0.0.0/8"), "10.0.0.1", &["::ffff:10.1.1.1"]),
            Err(Rejection::NoUntrustedClientIp)
        );
        assert_eq!(resolve(&t, "::ffff:8.8.8.8", &[]), Ok(ip("8.8.8.8")));
        // IPv4-compatible (not mapped) addresses are plain IPv6
        assert_eq!(
            resolve(
                &trusted("10.0.0.0/8, 127.0.0.1"),
                "127.0.0.1",
                &["::10.0.0.1"]
            ),
            Ok(ip("::10.0.0.1"))
        );
    }

    #[test]
    fn malformed_entry_before_untrusted_is_rejected() {
        let t = trusted("127.0.0.1");
        assert_eq!(
            resolve(&t, "127.0.0.1", &["6.6.6.6, not-an-ip, 127.0.0.1"]),
            Err(malformed("not-an-ip"))
        );
        // Ports, brackets, zone ids, and empty entries are malformed too
        for bad in ["1.2.3.4:80", "[::1]", "fe80::1%eth0", "", "unknown"] {
            assert_eq!(
                resolve(&t, "127.0.0.1", &[&format!("8.8.8.8, {bad}, 127.0.0.1")]),
                Err(malformed(bad)),
                "{bad:?}"
            );
        }
        assert_eq!(resolve(&t, "127.0.0.1", &["8.8.8.8,"]), Err(malformed("")));
        // A malformed entry to the left of the client is never reached
        assert_eq!(
            resolve(&t, "127.0.0.1", &["garbage, 8.8.8.8"]),
            Ok(ip("8.8.8.8"))
        );
        // Non-ASCII header value
        let mut headers = HeaderMap::new();
        headers.append(X_FORWARDED_FOR, HeaderValue::from_bytes(&[0xff]).unwrap());
        assert_eq!(
            rightmost_untrusted(&headers, ip("127.0.0.1"), &t),
            Err(client_ip::Error::NonAsciiHeaderValue {
                header_name: X_FORWARDED_FOR
            }
            .into())
        );
    }

    #[test]
    fn all_trusted_is_rejected() {
        let t = trusted("127.0.0.1, 10.0.0.0/8");
        assert_eq!(
            resolve(&t, "127.0.0.1", &["10.0.0.1, 10.0.0.2"]),
            Err(Rejection::NoUntrustedClientIp)
        );
        assert_eq!(
            resolve(&t, "127.0.0.1", &[]),
            Err(Rejection::NoUntrustedClientIp)
        );
        // No trusted networks at all: the peer is the client
        assert_eq!(
            resolve(&TrustedProxies::default(), "127.0.0.1", &["10.0.0.1"]),
            Ok(ip("127.0.0.1"))
        );
    }

    #[test]
    fn entry_limit() {
        let t = trusted("10.0.0.0/8, 127.0.0.1");
        let with_client =
            |trusted_hops: usize| format!("8.8.8.8, {}", vec!["10.0.0.1"; trusted_hops].join(", "));
        // The client is the last of `MAX_FORWARDED_ENTRIES` examined entries
        assert_eq!(
            resolve(&t, "127.0.0.1", &[&with_client(MAX_FORWARDED_ENTRIES - 1)]),
            Ok(ip("8.8.8.8"))
        );
        assert_eq!(
            resolve(&t, "127.0.0.1", &[&with_client(MAX_FORWARDED_ENTRIES)]),
            Err(Rejection::TooManyForwardedEntries)
        );
        // A huge header is rejected without being parsed in full
        let huge = format!("8.8.8.8, {}10.0.0.1", "10.0.0.1,".repeat(8 * 1024));
        assert_eq!(
            resolve(&t, "127.0.0.1", &[&huge]),
            Err(Rejection::TooManyForwardedEntries)
        );
        // The limit spans all headers
        let many: Vec<&str> = vec!["10.0.0.1"; MAX_FORWARDED_ENTRIES + 1];
        assert_eq!(
            resolve(&t, "127.0.0.1", &many),
            Err(Rejection::TooManyForwardedEntries)
        );
    }

    #[test]
    fn missing_extensions_are_rejected() {
        let request = |has_trusted: bool, has_peer: bool| {
            let mut req = Request::builder()
                .header("x-forwarded-for", "8.8.8.8")
                .body(())
                .unwrap();
            if has_trusted {
                req.extensions_mut().insert(trusted("127.0.0.1"));
            }
            if has_peer {
                req.extensions_mut()
                    .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1234))));
            }
            req.into_parts().0
        };
        assert_eq!(ip_from_parts(&request(true, true)), Ok(ip("8.8.8.8")));
        assert_eq!(
            ip_from_parts(&request(true, false)),
            Err(Rejection::NoConnectInfo)
        );
        assert_eq!(
            ip_from_parts(&request(false, true)),
            Err(Rejection::NoTrustedProxies)
        );
    }

    #[tokio::test]
    async fn extractor_through_router() {
        use axum::{Router, body::Body, http::StatusCode, routing::get};
        use tower::ServiceExt;

        let app = Router::new()
            .route(
                "/",
                get(|RightmostUntrustedXForwardedFor(ip)| async move { ip.to_string() }),
            )
            .layer(trusted("127.0.0.1").into_extension());
        let mut req = Request::builder()
            .uri("/")
            .header("x-forwarded-for", "6.6.6.6, 8.8.8.8")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1))));
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], b"8.8.8.8");

        // No `ConnectInfo`
        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn client_ip_source_variant() {
        use axum::{Router, body::Body, http::StatusCode, routing::get};
        use tower::ServiceExt;

        use crate::{ClientIp, ClientIpSource};

        let app = |with_proxies: bool| {
            let app = Router::new()
                .route("/", get(|ClientIp(ip)| async move { ip.to_string() }))
                .layer(ClientIpSource::RightmostUntrustedXForwardedFor.into_extension());
            if with_proxies {
                app.layer(trusted("127.0.0.1").into_extension())
            } else {
                app
            }
        };
        let request = || {
            let mut req = Request::builder()
                .uri("/")
                .header("x-forwarded-for", "6.6.6.6, 8.8.8.8")
                .body(Body::empty())
                .unwrap();
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1))));
            req
        };
        let resp = app(true).oneshot(request()).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], b"8.8.8.8");

        let resp = app(false).oneshot(request()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn cidr_edge_cases() {
        // /0 matches the whole family only
        assert!(cidr("0.0.0.0/0").contains(ip("203.0.113.1")));
        assert!(cidr("0.0.0.0/0").contains(ip("::ffff:203.0.113.1")));
        assert!(!cidr("0.0.0.0/0").contains(ip("2001:db8::1")));
        assert!(cidr("::/0").contains(ip("2001:db8::1")));
        assert!(!cidr("::/0").contains(ip("203.0.113.1")));
        // /32 and /128 are single hosts
        assert!(cidr("192.0.2.1/32").contains(ip("192.0.2.1")));
        assert!(!cidr("192.0.2.1/32").contains(ip("192.0.2.2")));
        assert!(cidr("2001:db8::1/128").contains(ip("2001:db8::1")));
        assert!(!cidr("2001:db8::1/128").contains(ip("2001:db8::2")));
        // A host address without a prefix
        assert_eq!(cidr("192.0.2.1"), cidr("192.0.2.1/32"));
        assert_eq!(cidr("2001:db8::1"), cidr("2001:db8::1/128"));
        assert!(!cidr("192.0.2.1").contains(ip("192.0.2.2")));
        // Host bits are ignored
        assert_eq!(cidr("10.1.2.3/8"), cidr("10.0.0.0/8"));
        assert_eq!(cidr("10.1.2.3/8").to_string(), "10.0.0.0/8");
        assert!(cidr("10.1.2.3/8").contains(ip("10.255.0.1")));
        assert!(!cidr("10.0.0.0/8").contains(ip("11.0.0.1")));
        assert!(cidr("173.245.48.0/20").contains(ip("173.245.63.255")));
        assert!(!cidr("173.245.48.0/20").contains(ip("173.245.64.0")));
        // Mapped networks become IPv4 networks
        assert_eq!(cidr("::ffff:10.0.0.0/104"), cidr("10.0.0.0/8"));
        assert_eq!(cidr("::ffff:10.0.0.1"), cidr("10.0.0.1/32"));
        assert_eq!(cidr("::ffff:0:0/96"), cidr("0.0.0.0/0"));
        // A shorter prefix is a plain IPv6 network that never matches IPv4
        assert!(!cidr("::ffff:10.0.0.0/95").contains(ip("10.0.0.1")));
        assert!(cidr("::ffff:10.0.0.0/95").contains(ip("::fffe:0:1")));
        // Invalid prefixes and addresses
        for bad in [
            "",
            "/8",
            "10.0.0.0/",
            "10.0.0.0/33",
            "2001:db8::/129",
            "::ffff:10.0.0.0/129",
            "10.0.0.0/-1",
            "10.0.0.0/+8",
            "10.0.0.0/8/8",
            "10.0.0.0/256",
            "10.0.0.0/ 8",
            "10.0.0/8",
            "example.com",
            "10.0.0.0/8x",
        ] {
            assert!(bad.parse::<Cidr>().is_err(), "{bad:?}");
        }
        assert!(cidr(" 10.0.0.0/8 ").contains(ip("10.0.0.1")));
    }

    #[test]
    fn trusted_proxies_from_str() {
        assert_eq!(trusted(""), TrustedProxies::default());
        assert_eq!(trusted("10.0.0.0/8,::1"), trusted(" 10.0.0.0/8 , ::1 "));
        assert!("10.0.0.0/8,".parse::<TrustedProxies>().is_err());
        assert!("10.0.0.0/8,nope".parse::<TrustedProxies>().is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn deserializes_from_env() {
        #[derive(serde::Deserialize)]
        struct Config {
            proxies: TrustedProxies,
        }
        let from_env =
            |value: &str| envy::from_iter::<_, Config>([("PROXIES".to_owned(), value.to_owned())]);
        assert_eq!(
            from_env("10.0.0.0/8,::1").unwrap().proxies,
            trusted("10.0.0.0/8, ::1")
        );
        assert!(from_env("10.0.0.0/99").is_err());
    }
}
