use crate::rejection::InfallibleRejection;
pub use crate::rejection::StringRejection;
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, HeaderMap},
};
use std::net::IpAddr;

/// Extracts a list of valid IP addresses from `X-Forwarded-For` header
#[derive(Debug)]
pub struct XForwardedFor(pub Vec<IpAddr>);

/// Extracts the leftmost IP from `X-Forwarded-For` header
///
/// Rejects with a 500 error if the header is absent or there's no valid IP
#[derive(Debug)]
pub struct LeftmostXForwardedFor(pub IpAddr);

/// Extracts the rightmost IP from `X-Forwarded-For` header
///
/// Rejects with a 500 error if the header is absent or there's no valid IP
#[derive(Debug)]
pub struct RightmostXForwardedFor(pub IpAddr);

/// Extracts a list of valid IP addresses from `Forwarded` header
#[derive(Debug)]
pub struct Forwarded(pub Vec<IpAddr>);

/// Extracts the leftmost IP from `Forwarded` header
///
/// Rejects with a 500 error if the header is absent or there's no valid IP
#[derive(Debug)]
pub struct LeftmostForwarded(pub IpAddr);

/// Extracts the rightmost IP from `Forwarded` header
///
/// Rejects with a 500 error if the header is absent or there's no valid IP
#[derive(Debug)]
pub struct RightmostForwarded(pub IpAddr);

/// Extracts a valid IP from `X-Real-Ip` (Nginx) header
///
/// Rejects with a 500 error if the header is absent or the IP isn't valid
#[derive(Debug)]
pub struct XRealIp(pub IpAddr);

/// Extracts a valid IP from `Fly-Client-IP` (Fly.io) header
///
/// When [FlyClientIp] extractor is run for health check path,
/// provide required `Fly-Client-IP` header through
/// [`services.http_checks.headers`](https://fly.io/docs/reference/configuration/#services-http_checks)
/// or [`http_service.checks.headers`](https://fly.io/docs/reference/configuration/#services-http_checks)
///
/// Rejects with a 500 error if the header is absent or the IP isn't valid
#[derive(Debug)]
pub struct FlyClientIp(pub IpAddr);

/// Extracts a valid IP from `True-Client-IP` (Akamai, Cloudflare) header
///
/// Rejects with a 500 error if the header is absent or the IP isn't valid
#[derive(Debug)]
pub struct TrueClientIp(pub IpAddr);

/// Extracts a valid IP from `CF-Connecting-IP` (Cloudflare) header
///
/// Rejects with a 500 error if the header is absent or the IP isn't valid
#[derive(Debug)]
pub struct CfConnectingIp(pub IpAddr);

pub(crate) trait SingleIpHeader {
    const HEADER: &'static str;

    fn maybe_ip_from_headers(headers: &HeaderMap) -> Option<IpAddr> {
        headers
            .get(Self::HEADER)
            .and_then(|hv| hv.to_str().ok())
            .and_then(|s| s.parse::<IpAddr>().ok())
    }

    fn ip_from_headers(headers: &HeaderMap) -> Result<IpAddr, StringRejection> {
        Self::maybe_ip_from_headers(headers).ok_or_else(|| Self::rejection())
    }

    fn rejection() -> StringRejection {
        format!("No `{}` header, or the IP is invalid", Self::HEADER).into()
    }
}

pub(crate) trait MultiIpHeader {
    const HEADER: &'static str;

    fn ips_from_header_value(header_value: &str) -> Vec<IpAddr>;

    fn ips_from_headers(headers: &HeaderMap) -> Vec<IpAddr> {
        headers
            .get_all(Self::HEADER)
            .iter()
            .filter_map(|hv| hv.to_str().ok())
            .flat_map(Self::ips_from_header_value)
            .collect()
    }

    fn maybe_leftmost_ip(headers: &HeaderMap) -> Option<IpAddr> {
        headers
            .get_all(Self::HEADER)
            .iter()
            .filter_map(|hv| hv.to_str().ok())
            .flat_map(Self::ips_from_header_value)
            .next()
    }

    fn leftmost_ip(headers: &HeaderMap) -> Result<IpAddr, StringRejection> {
        Self::maybe_leftmost_ip(headers).ok_or_else(|| Self::rejection())
    }

    fn maybe_rightmost_ip(headers: &HeaderMap) -> Option<IpAddr> {
        headers
            .get_all(Self::HEADER)
            .iter()
            .filter_map(|hv| hv.to_str().ok())
            .flat_map(Self::ips_from_header_value)
            .next_back()
    }

    fn rightmost_ip(headers: &HeaderMap) -> Result<IpAddr, StringRejection> {
        Self::maybe_rightmost_ip(headers).ok_or_else(|| Self::rejection())
    }

    fn rejection() -> StringRejection {
        format!("Couldn't find a valid IP in the `{}` header", Self::HEADER).into()
    }
}

macro_rules! impl_single_header {
    ($type:ty, $header:literal) => {
        impl SingleIpHeader for $type {
            const HEADER: &'static str = $header;
        }

        #[async_trait]
        impl<S> FromRequestParts<S> for $type
        where
            S: Sync,
        {
            type Rejection = StringRejection;

            async fn from_request_parts(
                parts: &mut Parts,
                _state: &S,
            ) -> Result<Self, Self::Rejection> {
                Ok(Self(
                    Self::maybe_ip_from_headers(&parts.headers).ok_or_else(Self::rejection)?,
                ))
            }
        }
    };
}

impl_single_header!(XRealIp, "X-Real-Ip");
impl_single_header!(FlyClientIp, "Fly-Client-IP");
impl_single_header!(TrueClientIp, "True-Client-IP");
impl_single_header!(CfConnectingIp, "CF-Connecting-IP");

impl MultiIpHeader for XForwardedFor {
    const HEADER: &'static str = "X-Forwarded-For";

    fn ips_from_header_value(header_value: &str) -> Vec<IpAddr> {
        header_value
            .split(',')
            .filter_map(|s| s.trim().parse::<IpAddr>().ok())
            .collect()
    }
}

impl MultiIpHeader for Forwarded {
    const HEADER: &'static str = "Forwarded";

    fn ips_from_header_value(header_value: &str) -> Vec<IpAddr> {
        use forwarded_header_value::{ForwardedHeaderValue, Identifier};

        let Ok(fv) = ForwardedHeaderValue::from_forwarded(header_value) else {return Vec::new()};
        fv.iter()
            .filter_map(|fs| fs.forwarded_for.as_ref())
            .filter_map(|ff| match ff {
                Identifier::SocketAddr(a) => Some(a.ip()),
                Identifier::IpAddr(ip) => Some(*ip),
                _ => None,
            })
            .collect()
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for XForwardedFor
where
    S: Sync,
{
    type Rejection = InfallibleRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(Self::ips_from_headers(&parts.headers)))
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for LeftmostXForwardedFor
where
    S: Sync,
{
    type Rejection = StringRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(
            XForwardedFor::maybe_leftmost_ip(&parts.headers)
                .ok_or_else(XForwardedFor::rejection)?,
        ))
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for RightmostXForwardedFor
where
    S: Sync,
{
    type Rejection = StringRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(
            XForwardedFor::maybe_rightmost_ip(&parts.headers)
                .ok_or_else(XForwardedFor::rejection)?,
        ))
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for Forwarded
where
    S: Sync,
{
    type Rejection = InfallibleRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(Self::ips_from_headers(&parts.headers)))
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for LeftmostForwarded
where
    S: Sync,
{
    type Rejection = StringRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(
            Forwarded::maybe_leftmost_ip(&parts.headers).ok_or_else(Forwarded::rejection)?,
        ))
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for RightmostForwarded
where
    S: Sync,
{
    type Rejection = StringRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(
            Forwarded::maybe_rightmost_ip(&parts.headers).ok_or_else(Forwarded::rejection)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CfConnectingIp, FlyClientIp, Forwarded, LeftmostForwarded, LeftmostXForwardedFor,
        RightmostForwarded, RightmostXForwardedFor, TrueClientIp, XForwardedFor, XRealIp,
    };
    use axum::{
        body::{Body, BoxBody},
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    async fn body_string(body: BoxBody) -> String {
        let bytes = hyper::body::to_bytes(body).await.unwrap();
        String::from_utf8_lossy(&bytes).into()
    }

    #[tokio::test]
    async fn x_real_ip() {
        fn app() -> Router {
            Router::new().route("/", get(|ip: XRealIp| async move { ip.0.to_string() }))
        }

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let req = Request::builder()
            .uri("/")
            .header("X-Real-Ip", "1.2.3.4")
            .body(Body::empty())
            .unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(body_string(res.into_body()).await, "1.2.3.4");
    }

    #[tokio::test]
    async fn fly_client_ip() {
        fn app() -> Router {
            Router::new().route("/", get(|ip: FlyClientIp| async move { ip.0.to_string() }))
        }

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let req = Request::builder()
            .uri("/")
            .header("Fly-Client-IP", "1.2.3.4")
            .body(Body::empty())
            .unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(body_string(res.into_body()).await, "1.2.3.4");
    }

    #[tokio::test]
    async fn true_client_ip() {
        fn app() -> Router {
            Router::new().route("/", get(|ip: TrueClientIp| async move { ip.0.to_string() }))
        }

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let req = Request::builder()
            .uri("/")
            .header("True-Client-IP", "1.2.3.4")
            .body(Body::empty())
            .unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(body_string(res.into_body()).await, "1.2.3.4");
    }

    #[tokio::test]
    async fn cf_connecting_ip() {
        fn app() -> Router {
            Router::new().route(
                "/",
                get(|ip: CfConnectingIp| async move { ip.0.to_string() }),
            )
        }

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let req = Request::builder()
            .uri("/")
            .header("CF-Connecting-IP", "1.2.3.4")
            .body(Body::empty())
            .unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(body_string(res.into_body()).await, "1.2.3.4");
    }

    #[tokio::test]
    async fn x_forwarded_for() {
        fn app() -> Router {
            Router::new().route(
                "/",
                get(|ips: XForwardedFor| async move { format!("{:?}", ips.0) }),
            )
        }

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(body_string(res.into_body()).await, "[]");

        let req = Request::builder()
            .uri("/")
            .header(
                "X-Forwarded-For",
                "1.1.1.1, foo, 2001:db8:85a3:8d3:1319:8a2e:370:7348",
            )
            .header("X-Forwarded-For", "bar")
            .header("X-Forwarded-For", "2.2.2.2")
            .body(Body::empty())
            .unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(
            body_string(res.into_body()).await,
            "[1.1.1.1, 2001:db8:85a3:8d3:1319:8a2e:370:7348, 2.2.2.2]"
        );
    }

    #[tokio::test]
    async fn leftmost_x_forwarded_for() {
        fn app() -> Router {
            Router::new().route(
                "/",
                get(|ip: LeftmostXForwardedFor| async move { format!("{:?}", ip.0) }),
            )
        }

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let req = Request::builder()
            .uri("/")
            .header(
                "X-Forwarded-For",
                "1.1.1.1, foo, 2001:db8:85a3:8d3:1319:8a2e:370:7348",
            )
            .header("X-Forwarded-For", "bar")
            .header("X-Forwarded-For", "2.2.2.2")
            .body(Body::empty())
            .unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(body_string(res.into_body()).await, "1.1.1.1");
    }

    #[tokio::test]
    async fn rightmost_x_forwarded_for() {
        fn app() -> Router {
            Router::new().route(
                "/",
                get(|ip: RightmostXForwardedFor| async move { format!("{:?}", ip.0) }),
            )
        }

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let req = Request::builder()
            .uri("/")
            .header(
                "X-Forwarded-For",
                "1.1.1.1, foo, 2001:db8:85a3:8d3:1319:8a2e:370:7348",
            )
            .header("X-Forwarded-For", "bar")
            .header("X-Forwarded-For", "2.2.2.2, 3.3.3.3")
            .body(Body::empty())
            .unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(body_string(res.into_body()).await, "3.3.3.3");
    }

    #[tokio::test]
    async fn forwarded() {
        fn app() -> Router {
            Router::new().route(
                "/",
                get(|ips: Forwarded| async move { format!("{:?}", ips.0) }),
            )
        }

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(body_string(res.into_body()).await, "[]");

        let req = Request::builder()
            .uri("/")
            .header("Forwarded", r#"for="_mdn""#)
            .header("Forwarded", r#"For="[2001:db8:cafe::17]:4711""#)
            .header("Forwarded", r#"for=192.0.2.60;proto=http;by=203.0.113.43"#)
            .body(Body::empty())
            .unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(
            body_string(res.into_body()).await,
            "[2001:db8:cafe::17, 192.0.2.60]"
        );
    }

    #[tokio::test]
    async fn leftmost_forwarded() {
        fn app() -> Router {
            Router::new().route(
                "/",
                get(|ip: LeftmostForwarded| async move { format!("{:?}", ip.0) }),
            )
        }

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let req = Request::builder()
            .uri("/")
            .header("Forwarded", r#"for="_mdn""#)
            .header("Forwarded", r#"For="[2001:db8:cafe::17]:4711""#)
            .header("Forwarded", r#"for=192.0.2.60;proto=http;by=203.0.113.43"#)
            .body(Body::empty())
            .unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(body_string(res.into_body()).await, "2001:db8:cafe::17");
    }

    #[tokio::test]
    async fn rightmost_forwarded() {
        fn app() -> Router {
            Router::new().route(
                "/",
                get(|ip: RightmostForwarded| async move { format!("{:?}", ip.0) }),
            )
        }

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let req = Request::builder()
            .uri("/")
            .header("Forwarded", r#"for="_mdn""#)
            .header("Forwarded", r#"For="[2001:db8:cafe::17]:4711""#)
            .header("Forwarded", r#"for=192.0.2.60;proto=http;by=203.0.113.43"#)
            .body(Body::empty())
            .unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(body_string(res.into_body()).await, "192.0.2.60");
    }
}
