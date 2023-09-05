use crate::rudimental::{
    CfConnectingIp, FlyClientIp, Forwarded, MultiIpHeader, SingleIpHeader, TrueClientIp,
    XForwardedFor, XRealIp,
};
use axum::{
    async_trait,
    extract::{ConnectInfo, FromRequestParts},
    http::{request::Parts, Extensions, HeaderMap, HeaderValue, StatusCode},
};
use std::{
    marker::Sync,
    net::{IpAddr, SocketAddr},
};

/// An insecure client IP extractor - no security, but somehow better IP determination
///
/// This extractor is meant for cases when you'd prefer to **sacrifice security** for probably
/// statistically **better IP determination**. A good usage example would be IP-based geolocation if
/// the wrong location won't be a security issue for your app. But for something like rate limiting you
/// certainly should use [`crate::SecureClientIp`] instead.
///
/// Technically it means looking for leftmost IP addresses provided by forward proxy first, and then look into single
/// IP headers like `X-Real-Ip`, and then falling back to the [`axum::extract::ConnectInfo`].
///
/// It returns a 500 error if you forget to provide the `ConnectInfo` with e.g.
/// [`axum::routing::Router::into_make_service_with_connect_info`]
///
/// Here's a configuration [example][].
///
/// [example]: https://github.com/imbolc/axum-client-ip/blob/main/examples/insecure.rs
#[derive(Debug)]
pub struct InsecureClientIp(pub IpAddr);

type Rejection = (StatusCode, &'static str);

impl InsecureClientIp {
    /// Try to extract client IP from given arguments.
    ///
    /// # Errors
    ///
    /// This function will return an error if cannot extract IP.
    pub fn from(
        headers: &HeaderMap<HeaderValue>,
        extensions: &Extensions,
    ) -> Result<Self, Rejection> {
        XForwardedFor::maybe_leftmost_ip(headers)
            .or_else(|| Forwarded::maybe_leftmost_ip(headers))
            .or_else(|| XRealIp::maybe_ip_from_headers(headers))
            .or_else(|| FlyClientIp::maybe_ip_from_headers(headers))
            .or_else(|| TrueClientIp::maybe_ip_from_headers(headers))
            .or_else(|| CfConnectingIp::maybe_ip_from_headers(headers))
            .or_else(|| maybe_connect_info(extensions))
            .map(Self)
            .ok_or((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Can't extract `UnsecureClientIp`, provide `axum::extract::ConnectInfo`",
            ))
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for InsecureClientIp
where
    S: Sync,
{
    type Rejection = Rejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Self::from(&parts.headers, &parts.extensions)
    }
}

/// Looks for an IP in the [`axum::extract::ConnectInfo`] extension
fn maybe_connect_info(extensions: &Extensions) -> Option<IpAddr> {
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
}

#[cfg(test)]
mod tests {
    use super::InsecureClientIp;
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
            get(|InsecureClientIp(ip): InsecureClientIp| async move { ip.to_string() }),
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
