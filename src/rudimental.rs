use std::net::IpAddr;

use axum::{
    extract::FromRequestParts,
    http::{HeaderMap, request::Parts},
};

use crate::rejection::{InfallibleRejection, StringRejection};

/// Extracts a list of valid IP addresses from `X-Forwarded-For` header
#[derive(Debug)]
pub struct XForwardedFor(pub Vec<IpAddr>);

/// Extracts the leftmost IP from `X-Forwarded-For` header
///
/// Rejects with a 500 error if the header is absent or there's no valid IP
#[derive(Debug, Clone, Copy)]
pub struct LeftmostXForwardedFor(pub IpAddr);

/// Extracts the rightmost IP from `X-Forwarded-For` header
///
/// Rejects with a 500 error if the header is absent or there's no valid IP
#[derive(Debug, Clone, Copy)]
pub struct RightmostXForwardedFor(pub IpAddr);

/// Extracts a list of valid IP addresses from `Forwarded` header
#[derive(Debug)]
pub struct Forwarded(pub Vec<IpAddr>);

/// Extracts the leftmost IP from `Forwarded` header
///
/// Rejects with a 500 error if the header is absent or there's no valid IP
#[derive(Debug, Clone, Copy)]
pub struct LeftmostForwarded(pub IpAddr);

/// Extracts the rightmost IP from `Forwarded` header
///
/// Rejects with a 500 error if the header is absent or there's no valid IP
#[derive(Debug, Clone, Copy)]
pub struct RightmostForwarded(pub IpAddr);

/// Extracts a valid IP from `X-Real-Ip` (Nginx) header
///
/// Rejects with a 500 error if the header is absent or the IP isn't valid
#[derive(Debug, Clone, Copy)]
pub struct XRealIp(pub IpAddr);

/// Extracts a valid IP from `Fly-Client-IP` (Fly.io) header
///
/// When [FlyClientIp] extractor is run for health check path,
/// provide required `Fly-Client-IP` header through
/// [`services.http_checks.headers`](https://fly.io/docs/reference/configuration/#services-http_checks)
/// or [`http_service.checks.headers`](https://fly.io/docs/reference/configuration/#services-http_checks)
///
/// Rejects with a 500 error if the header is absent or the IP isn't valid
#[derive(Debug, Clone, Copy)]
pub struct FlyClientIp(pub IpAddr);

/// Extracts a valid IP from `True-Client-IP` (Akamai, Cloudflare) header
///
/// Rejects with a 500 error if the header is absent or the IP isn't valid
#[derive(Debug, Clone, Copy)]
pub struct TrueClientIp(pub IpAddr);

/// Extracts a valid IP from `CF-Connecting-IP` (Cloudflare) header
///
/// Rejects with a 500 error if the header is absent or the IP isn't valid
#[derive(Debug, Clone, Copy)]
pub struct CfConnectingIp(pub IpAddr);

/// Extracts a valid IP from `CloudFront-Viewer-Address` (AWS CloudFront) header
///
/// Rejects with a 500 error if the header is absent or the IP isn't valid
#[derive(Debug, Clone, Copy)]
pub struct CloudFrontViewerAddress(pub IpAddr);

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

impl SingleIpHeader for CloudFrontViewerAddress {
    const HEADER: &'static str = "cloudfront-viewer-address";

    fn maybe_ip_from_headers(headers: &HeaderMap) -> Option<IpAddr> {
        headers
            .get(Self::HEADER)
            .and_then(|hv| hv.to_str().ok())
            // Spec: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/adding-cloudfront-headers.html#cloudfront-headers-viewer-location
            // Note: Both IPv4 and IPv6 addresses (in the specified format) do not contain
            //       non-ascii characters, so no need to handle percent-encoding.
            //
            //       CloudFront does not use `[::]:12345` style notation for IPv6 (unfortunately),
            //       otherwise parsing via `SocketAddr` would be possible.
            .and_then(|hv| hv.rsplit_once(':').map(|(ip, _port)| ip))
            .and_then(|s| s.parse::<IpAddr>().ok())
    }
}

impl<S> FromRequestParts<S> for CloudFrontViewerAddress
where
    S: Sync,
{
    type Rejection = StringRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(
            Self::maybe_ip_from_headers(&parts.headers).ok_or_else(Self::rejection)?,
        ))
    }
}

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

        let Ok(fv) = ForwardedHeaderValue::from_forwarded(header_value) else {
            return Vec::new();
        };
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

impl<S> FromRequestParts<S> for XForwardedFor
where
    S: Sync,
{
    type Rejection = InfallibleRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(Self::ips_from_headers(&parts.headers)))
    }
}

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

impl<S> FromRequestParts<S> for Forwarded
where
    S: Sync,
{
    type Rejection = InfallibleRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(Self::ips_from_headers(&parts.headers)))
    }
}

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
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        routing::get,
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::{
        CfConnectingIp, FlyClientIp, Forwarded, LeftmostForwarded, LeftmostXForwardedFor,
        RightmostForwarded, RightmostXForwardedFor, TrueClientIp, XForwardedFor, XRealIp,
    };

    async fn body_string(body: Body) -> String {
        let bytes = body.collect().await.unwrap().to_bytes();
        String::from_utf8_lossy(&bytes).into()
    }

    #[tokio::test]
    async fn x_real_ip() {
        fn app() -> Router {
            Router::new().route("/", get(|ip: XRealIp| async move { ip.0.to_string() }))
        }

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let req = Request::builder()
            .uri("/")
            .header("X-Real-Ip", "1.2.3.4")
            .body(Body::empty())
            .unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(body_string(resp.into_body()).await, "1.2.3.4");
    }

    #[tokio::test]
    async fn fly_client_ip() {
        fn app() -> Router {
            Router::new().route("/", get(|ip: FlyClientIp| async move { ip.0.to_string() }))
        }

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let req = Request::builder()
            .uri("/")
            .header("Fly-Client-IP", "1.2.3.4")
            .body(Body::empty())
            .unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(body_string(resp.into_body()).await, "1.2.3.4");
    }

    #[tokio::test]
    async fn true_client_ip() {
        fn app() -> Router {
            Router::new().route("/", get(|ip: TrueClientIp| async move { ip.0.to_string() }))
        }

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let req = Request::builder()
            .uri("/")
            .header("True-Client-IP", "1.2.3.4")
            .body(Body::empty())
            .unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(body_string(resp.into_body()).await, "1.2.3.4");
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
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let req = Request::builder()
            .uri("/")
            .header("CF-Connecting-IP", "1.2.3.4")
            .body(Body::empty())
            .unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(body_string(resp.into_body()).await, "1.2.3.4");
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
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(body_string(resp.into_body()).await, "[]");

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
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(
            body_string(resp.into_body()).await,
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
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

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
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(body_string(resp.into_body()).await, "1.1.1.1");
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
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

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
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(body_string(resp.into_body()).await, "3.3.3.3");
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
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(body_string(resp.into_body()).await, "[]");

        let req = Request::builder()
            .uri("/")
            .header("Forwarded", r#"for="_mdn""#)
            .header("Forwarded", r#"For="[2001:db8:cafe::17]:4711""#)
            .header("Forwarded", r#"for=192.0.2.60;proto=http;by=203.0.113.43"#)
            .body(Body::empty())
            .unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(
            body_string(resp.into_body()).await,
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
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let req = Request::builder()
            .uri("/")
            .header("Forwarded", r#"for="_mdn""#)
            .header("Forwarded", r#"For="[2001:db8:cafe::17]:4711""#)
            .header("Forwarded", r#"for=192.0.2.60;proto=http;by=203.0.113.43"#)
            .body(Body::empty())
            .unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(body_string(resp.into_body()).await, "2001:db8:cafe::17");
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
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let req = Request::builder()
            .uri("/")
            .header("Forwarded", r#"for="_mdn""#)
            .header("Forwarded", r#"For="[2001:db8:cafe::17]:4711""#)
            .header("Forwarded", r#"for=192.0.2.60;proto=http;by=203.0.113.43"#)
            .body(Body::empty())
            .unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(body_string(resp.into_body()).await, "192.0.2.60");
    }

    #[tokio::test]
    async fn cloudfront_viewer_addresps_ipv4() {
        fn app() -> Router {
            Router::new().route(
                "/",
                get(|ip: super::CloudFrontViewerAddress| async move { ip.0.to_string() }),
            )
        }

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let req = Request::builder()
            .uri("/")
            .header("CloudFront-Viewer-Address", "198.51.100.10:46532")
            .body(Body::empty())
            .unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(body_string(resp.into_body()).await, "198.51.100.10");
    }

    #[tokio::test]
    async fn cloudfront_viewer_addresps_ipv6() {
        fn app() -> Router {
            Router::new().route(
                "/",
                get(|ip: super::CloudFrontViewerAddress| async move { ip.0.to_string() }),
            )
        }

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let req = Request::builder()
            .uri("/")
            .header(
                "CloudFront-Viewer-Address",
                "2a09:bac1:3b20:38::17e:7:51786",
            )
            .body(Body::empty())
            .unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(
            body_string(resp.into_body()).await,
            "2a09:bac1:3b20:38::17e:7"
        );
    }
}
