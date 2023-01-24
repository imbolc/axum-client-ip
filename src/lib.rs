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
    http::{header::FORWARDED, request::Parts, Extensions, HeaderMap, StatusCode},
};
use forwarded_header_value::{ForwardedHeaderValue, Identifier};
use std::{
    marker::Sync,
    net::{IpAddr, SocketAddr},
    sync::Mutex,
};

const X_REAL_IP: &str = "x-real-ip";
const X_FORWARDED_FOR: &str = "x-forwarded-for";

/// Extractor for the client IP address
pub struct ClientIp(pub IpAddr);

type IpFromHeaders = fn(&HeaderMap) -> Option<IpAddr>;
static ORDER: Mutex<Option<Vec<IpFromHeaders>>> = Mutex::new(None);
const DEFAULT_ORDER: &[IpFromHeaders] = &[maybe_x_forwarded_for, maybe_x_real_ip, maybe_forwarded];

/// Sets IP extraction order
pub fn set_order(new_order: &[IpFromHeaders]) {
    let mut order = ORDER.lock().unwrap();
    *order = Some(new_order.into());
}

fn find_ip(headers: &HeaderMap) -> Option<IpAddr> {
    let mut order = ORDER.lock().unwrap();
    if order.is_none() {
        *order = Some(DEFAULT_ORDER.into());
    }
    order.as_ref().unwrap().iter().find_map(|f| f(headers))
}

#[async_trait]
impl<S> FromRequestParts<S> for ClientIp
where
    S: Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        find_ip(&parts.headers)
            .or_else(|| maybe_connect_info(&parts.extensions))
            .map(Self)
            .ok_or((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Can't determine the client IP, check forwarding configuration",
            ))
    }
}

/// Tries to parse the `x-forwarded-for` header
/// It treats the leftmost IP of the first header as belonging to the client
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
            .header("X-Forwarded-For", "3.3.3.3, 4.4.4.4")
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

    #[tokio::test]
    async fn change_extractors_order() {
        let req = Request::builder()
            .uri("/")
            .header("X-Real-Ip", "1.1.1.1")
            .header("Forwarded", "For=\"2.2.2.2\"")
            .body(Body::empty())
            .unwrap();

        let res = app().oneshot(req).await.unwrap();
        assert_eq!(body_string(res.into_body()).await, "1.1.1.1");

        let req = Request::builder()
            .uri("/")
            .header("X-Real-Ip", "1.1.1.1")
            .header("Forwarded", "For=\"2.2.2.2\"")
            .body(Body::empty())
            .unwrap();

        crate::set_order(&[crate::maybe_forwarded]);

        let res = app().oneshot(req).await.unwrap();
        assert_eq!(body_string(res.into_body()).await, "2.2.2.2");

        crate::set_order(crate::DEFAULT_ORDER);
    }
}
