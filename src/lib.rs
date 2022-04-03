//! A client IP address extractor for Axum
//!
//! It sequentially looks for an IP in:
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
//!             app.into_make_service_with_connect_info::<SocketAddr>()
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

/// Extractor for the client IP address
pub struct ClientIp(pub IpAddr);

#[async_trait]
impl<B> FromRequest<B> for ClientIp
where
    B: Send,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let headers = req.headers();

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

/// Tries to parse the `x-real-ip` header
fn maybe_x_forwarded_for(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get(X_FORWARDED_FOR)
        .and_then(|hv| hv.to_str().ok())
        .and_then(|s| s.split(',').find_map(|s| s.trim().parse::<IpAddr>().ok()))
}

/// Tries to parse the `x-real-ip` header
fn maybe_x_real_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get(X_REAL_IP)
        .and_then(|hv| hv.to_str().ok())
        .and_then(|s| s.parse::<IpAddr>().ok())
}

/// Tries to parse `forwarded` headers
fn maybe_forwarded(headers: &HeaderMap) -> Option<IpAddr> {
    headers.get_all(FORWARDED).iter().find_map(|hv| {
        hv.to_str()
            .ok()
            .and_then(|s| ForwardedHeaderValue::from_forwarded(s).ok())
            .and_then(|f| {
                f.iter()
                    .filter_map(|fs| fs.forwarded_for.as_ref())
                    .find_map(|ff| match ff {
                        Identifier::SocketAddr(a) => Some(a.ip()),
                        Identifier::IpAddr(ip) => Some(*ip),
                        _ => None,
                    })
            })
    })
}

/// Looks in `ConnectInfo` extension
fn maybe_connect_info<B: Send>(req: &RequestParts<B>) -> Option<IpAddr> {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
}

#[cfg(test)]
mod tests {
    use crate::ClientIp;
    use axum::{
        body::{Body, BoxBody},
        http::Request,
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    fn app() -> Router {
        Router::new().route(
            "/",
            get(|ClientIp(ip): ClientIp| async move { ip.to_string() }),
        )
    }

    async fn body_string(body: BoxBody) -> String {
        let bytes = hyper::body::to_bytes(body).await.unwrap();
        String::from_utf8_lossy(&bytes).into()
    }

    #[tokio::test]
    async fn x_forwarded_for() {
        let req = Request::builder()
            .uri("/")
            .header("X-Forwarded-For", "1.1.1.1, 2.2.2.2")
            .body(Body::empty())
            .unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(body_string(res.into_body()).await, "1.1.1.1");
    }

    #[tokio::test]
    async fn x_real_ip() {
        let req = Request::builder()
            .uri("/")
            .header("X-Real-Ip", "1.2.3.4")
            .body(Body::empty())
            .unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(body_string(res.into_body()).await, "1.2.3.4");
    }

    #[tokio::test]
    async fn forwarded() {
        let req = Request::builder()
            .uri("/")
            .header("Forwarded", "For=\"[2001:db8:cafe::17]:4711\"")
            .body(Body::empty())
            .unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(body_string(res.into_body()).await, "2001:db8:cafe::17");
    }

    #[tokio::test]
    async fn malformed() {
        let req = Request::builder()
            .uri("/")
            .header("X-Forwarded-For", "foo")
            .header("X-Real-Ip", "foo")
            .header("Forwarded", "foo")
            .header("Forwarded", "for=1.1.1.1;proto=https;by=2.2.2.2")
            .body(Body::empty())
            .unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(body_string(res.into_body()).await, "1.1.1.1");
    }
}
