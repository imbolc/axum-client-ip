//! A client IP address extractor for Axum
//!
//! It sequentially tries to find a non-local ip in:
//!
//! - `x-forwarded-for` header (de-facto standard)
//! - `x-real-ip` header
//! - `forwarded` header (new standard)
//! - [`axum::extract::ConnectInfo`][connect-info] (if not behind proxy)
//!
//! ## Usage
//!
//! ```rust,no_run
//! use axum::{extract::ConnectInfo, routing::get, Router};
//! use axum_client_ip::ClientIp;
//! use std::net::SocketAddr;
//!
//! pub async fn handler(ClientIp(ip): ClientIp) -> String {
//!     ip.to_string()
//! }
//!
//! #[tokio::main]
//! async fn main() {
//!     let app = Router::new().route("/", get(handler));
//!
//!     axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
//!         .serve(
//!             // Don't forget to add `ConnetInfo` if you aren't behind a proxy
//!             app.into_make_service_with_connect_info::<SocketAddr, _>()
//!         )
//!         .await
//!         .unwrap()
//! }
//! ```
//!
//! [connect-info]: https://docs.rs/axum/latest/axum/extract/struct.ConnectInfo.html

#![warn(clippy::all, missing_docs, nonstandard_style, future_incompatible)]

use axum::{
    async_trait,
    extract::{ConnectInfo, FromRequest, RequestParts},
    http::{header::FORWARDED, HeaderMap, StatusCode},
};
use forwarded_header_value::{ForwardedHeaderValue, Identifier};
use std::net::SocketAddr;

use std::net::IpAddr;

const X_REAL_IP: &str = "x-real-ip";
const X_FORWARDED_FOR: &str = "x-forwarded-for";

/// Extractor for the real client IP address
pub struct ClientIp(pub IpAddr);

#[async_trait]
impl<B> FromRequest<B> for ClientIp
where
    B: Send,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let headers = req.headers().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Can't extract client IP: headers has been taken by another extractor",
        ))?;

        maybe_x_forwarded_for(headers)
            .or_else(|| maybe_x_real_ip(headers))
            .or_else(|| maybe_forwarded(headers))
            .or_else(|| maybe_connect_info(req))
            .map(Self)
            .ok_or((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Can't determine the client IP, check forwarding configuration",
            ))
    }
}

/// Tries to find a non-local IP in the `x-forwarded-for` header
fn maybe_x_forwarded_for(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get(X_FORWARDED_FOR)
        .and_then(|hv| hv.to_str().ok())
        .and_then(|s| {
            s.split(',')
                .filter_map(|s| s.trim().parse::<IpAddr>().ok())
                .find(|ip| !is_local(ip))
        })
}

/// Tries to find a non-local IP in the `x-real-ip` header
fn maybe_x_real_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get(X_REAL_IP)
        .and_then(|hv| hv.to_str().ok())
        .and_then(|s| s.parse::<IpAddr>().ok())
        .filter(|ip| !is_local(ip))
}

/// Tries to find a non-local IP in a `forwarded` header
fn maybe_forwarded(headers: &HeaderMap) -> Option<IpAddr> {
    headers.get_all(FORWARDED).iter().find_map(|hv| {
        hv.to_str()
            .ok()
            .and_then(|s| ForwardedHeaderValue::from_forwarded(s).ok())
            .and_then(|f| {
                f.iter()
                    .filter_map(|fs| fs.forwarded_for.as_ref())
                    .filter_map(|ff| match ff {
                        Identifier::SocketAddr(a) => Some(a.ip()),
                        Identifier::IpAddr(ip) => Some(*ip),
                        _ => None,
                    })
                    .find(|ip| !is_local(ip))
            })
    })
}

/// Tries to find a non-local IP in the `ConnectInfo` extension
fn maybe_connect_info<B: Send>(req: &RequestParts<B>) -> Option<IpAddr> {
    req.extensions()
        .and_then(|e| e.get::<ConnectInfo<SocketAddr>>())
        .map(|ConnectInfo(addr)| addr.ip())
        .filter(|ip| !is_local(ip))
}

/// Check if it's a local IP, found in https://github.com/magiclen/rocket-client-addr/
fn is_local(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(addr) => {
            let octets = addr.octets();

            match octets {
                // --- is_private ---
                [10, ..] => true,
                [172, b, ..] if (16..=31).contains(&b) => true,
                [192, 168, ..] => true,
                // --- is_loopback ---
                [127, ..] => true,
                // --- is_link_local ---
                [169, 254, ..] => true,
                // --- is_broadcast ---
                [255, 255, 255, 255] => true,
                // --- is_documentation ---
                [192, 0, 2, _] => true,
                [198, 51, 100, _] => true,
                [203, 0, 113, _] => true,
                // --- is_unspecified ---
                [0, 0, 0, 0] => true,
                _ => false,
            }
        }
        IpAddr::V6(addr) => {
            let segments = addr.segments();

            let is_multicast = segments[0] & 0xff00 == 0xff00;

            if is_multicast {
                segments[0] & 0x000f != 14 // 14 means global
            } else {
                match segments {
                    // --- is_loopback ---
                    [0, 0, 0, 0, 0, 0, 0, 1] => true,
                    // --- is_unspecified ---
                    [0, 0, 0, 0, 0, 0, 0, 0] => true,
                    _ => {
                        match segments[0] & 0xffc0 {
                            // --- is_unicast_link_local ---
                            0xfe80 => true,
                            // --- is_unicast_site_local ---
                            0xfec0 => true,
                            _ => {
                                // --- is_unique_local ---
                                if segments[0] & 0xfe00 == 0xfc00 {
                                    true
                                } else {
                                    (segments[0] == 0x2001) && (segments[1] == 0xdb8)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
