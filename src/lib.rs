//! A client IP address extractor for Axum
//!
//! It sequentially looks for an IP in:
//!
//! - `x-forwarded-for` header (de-facto standard)
//! - `x-real-ip` header
//! - `forwarded` header (new standard)
//! - [`axum::extract::ConnectInfo`][connect-info] (if not behind proxy)
//!
//! The most often issue with this extractor is using it after one consuming body e.g. `Json`.
//! To fix this rearrange extractors in your handler definition moving body consumption to the
//! end, [details][extractors-order].
//!
//! ## Usage
//!
//! ```rust,no_run
//! use axum::{routing::get, Router};
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
//! [extractors-order]: https://docs.rs/axum/latest/axum/extract/index.html#the-order-of-extractors

#![warn(clippy::all, missing_docs, nonstandard_style, future_incompatible)]

use axum::{
    async_trait,
    extract::{ConnectInfo, FromRequestParts},
    http::{request::Parts, Extensions, StatusCode},
};
use std::{marker::Sync, net::SocketAddr};

use std::net::IpAddr;

mod rudimental;
pub use rudimental::{
    Forwarded, LeftmostForwarded, LeftmostXForwardedFor, RightmostForwarded,
    RightmostXForwardedFor, XForwardedFor, XRealIp,
};
use rudimental::{MultiIpHeader, SingleIpHeader};

/// Extractor for the client IP address
pub struct ClientIp(pub IpAddr);

#[async_trait]
impl<S> FromRequestParts<S> for ClientIp
where
    S: Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        XForwardedFor::leftmost_ip(&parts.headers)
            .or_else(|| XRealIp::ip_from_headers(&parts.headers))
            .or_else(|| Forwarded::leftmost_ip(&parts.headers))
            .or_else(|| maybe_connect_info(&parts.extensions))
            .map(Self)
            .ok_or((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Can't determine the client IP, check forwarding configuration",
            ))
    }
}

/// Looks in `ConnectInfo` extension
fn maybe_connect_info(extensions: &Extensions) -> Option<IpAddr> {
    extensions
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
