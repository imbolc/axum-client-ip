#![doc = include_str!("../README.md")]

pub use basic::{
    CfConnectingIp, CloudFrontViewerAddress, FlyClientIp, Forwarded, LeftmostForwarded,
    LeftmostXForwardedFor, RightmostForwarded, RightmostXForwardedFor, TrueClientIp, XForwardedFor,
    XRealIp,
};
pub use insecure::InsecureClientIp;
pub use secure::{SecureClientIp, SecureClientIpSource};

/// Basic extractors
mod basic {
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

    /// Extracts a valid IP from `CloudFront-Viewer-Address` (AWS CloudFront)
    /// header
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
                //       CloudFront does not use `[::]:12345` style notation for IPv6
                // (unfortunately),       otherwise parsing via `SocketAddr` would
                // be possible.
                .and_then(|hv| hv.rsplit_once(':').map(|(ip, _port)| ip))
                .and_then(|s| s.parse::<IpAddr>().ok())
        }
    }

    impl<S> FromRequestParts<S> for CloudFrontViewerAddress
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

        async fn from_request_parts(
            parts: &mut Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
            Ok(Self(Self::ips_from_headers(&parts.headers)))
        }
    }

    impl<S> FromRequestParts<S> for LeftmostXForwardedFor
    where
        S: Sync,
    {
        type Rejection = StringRejection;

        async fn from_request_parts(
            parts: &mut Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
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

        async fn from_request_parts(
            parts: &mut Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
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

        async fn from_request_parts(
            parts: &mut Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
            Ok(Self(Self::ips_from_headers(&parts.headers)))
        }
    }

    impl<S> FromRequestParts<S> for LeftmostForwarded
    where
        S: Sync,
    {
        type Rejection = StringRejection;

        async fn from_request_parts(
            parts: &mut Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
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

        async fn from_request_parts(
            parts: &mut Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
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
        use crate::CloudFrontViewerAddress;

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
                    get(|ip: CloudFrontViewerAddress| async move { ip.0.to_string() }),
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
                    get(|ip: CloudFrontViewerAddress| async move { ip.0.to_string() }),
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
}

mod secure {
    use std::{
        error::Error,
        fmt,
        marker::Sync,
        net::{IpAddr, SocketAddr},
        str::FromStr,
    };

    use axum::{
        extract::{ConnectInfo, Extension, FromRequestParts},
        http::{Extensions, HeaderMap, HeaderValue, request::Parts},
    };
    use serde::{Deserialize, Serialize};

    use crate::{
        basic::{
            CfConnectingIp, CloudFrontViewerAddress, FlyClientIp, Forwarded, MultiIpHeader,
            SingleIpHeader, TrueClientIp, XForwardedFor, XRealIp,
        },
        rejection::StringRejection,
    };

    /// A secure client IP extractor - can't be spoofed if configured correctly
    ///
    /// The configuration would include knowing the header the last proxy (the
    /// one you own or the one your cloud server provides) is using to store
    /// user connection IP. Then you'd need to pass a corresponding
    /// [`SecureClientIpSource`] variant into the
    /// [`axum::routing::Router::layer`] as an extension. Look at the
    /// [example][].
    ///
    /// [example]: https://github.com/imbolc/axum-client-ip/blob/main/examples/secure.rs
    #[derive(Debug, Clone, Copy)]
    pub struct SecureClientIp(pub IpAddr);

    /// [`SecureClientIp`] source configuration
    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub enum SecureClientIpSource {
        /// Rightmost IP from the `Forwarded` header
        RightmostForwarded,
        /// Rightmost IP from the `X-Forwarded-For` header
        RightmostXForwardedFor,
        /// IP from the `X-Real-Ip` header
        XRealIp,
        /// IP from the `Fly-Client-IP` header
        FlyClientIp,
        /// IP from the `True-Client-IP` header
        TrueClientIp,
        /// IP from the `CF-Connecting-IP` header
        CfConnectingIp,
        /// IP from the [`axum::extract::ConnectInfo`]
        ConnectInfo,
        /// IP from the `CloudFront-Viewer-Address` header
        CloudFrontViewerAddress,
    }

    impl SecureClientIpSource {
        /// Wraps `SecureClientIpSource` into the [`axum::extract::Extension`]
        /// for passing to [`axum::routing::Router::layer`]
        pub const fn into_extension(self) -> Extension<Self> {
            Extension(self)
        }
    }

    #[derive(Debug)]
    pub struct ParseSecureClientIpSourceError(String);

    impl fmt::Display for ParseSecureClientIpSourceError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Invalid SecureClientIpSource value {}", self.0)
        }
    }

    impl Error for ParseSecureClientIpSourceError {}

    impl FromStr for SecureClientIpSource {
        type Err = ParseSecureClientIpSourceError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            Ok(match s {
                "RightmostForwarded" => Self::RightmostForwarded,
                "RightmostXForwardedFor" => Self::RightmostXForwardedFor,
                "XRealIp" => Self::XRealIp,
                "FlyClientIp" => Self::FlyClientIp,
                "TrueClientIp" => Self::TrueClientIp,
                "CfConnectingIp" => Self::CfConnectingIp,
                "ConnectInfo" => Self::ConnectInfo,
                "CloudFrontViewerAddress" => Self::CloudFrontViewerAddress,
                _ => return Err(ParseSecureClientIpSourceError(s.to_string())),
            })
        }
    }

    impl SecureClientIp {
        /// Try to extract client IP from given arguments.
        ///
        /// # Errors
        ///
        /// This function will return an error if cannot extract IP.
        pub fn from(
            ip_source: &SecureClientIpSource,
            headers: &HeaderMap<HeaderValue>,
            extensions: &Extensions,
        ) -> Result<Self, StringRejection> {
            match ip_source {
                SecureClientIpSource::RightmostForwarded => Forwarded::rightmost_ip(headers),
                SecureClientIpSource::RightmostXForwardedFor => {
                    XForwardedFor::rightmost_ip(headers)
                }
                SecureClientIpSource::XRealIp => XRealIp::ip_from_headers(headers),
                SecureClientIpSource::FlyClientIp => FlyClientIp::ip_from_headers(headers),
                SecureClientIpSource::TrueClientIp => TrueClientIp::ip_from_headers(headers),
                SecureClientIpSource::CfConnectingIp => CfConnectingIp::ip_from_headers(headers),
                SecureClientIpSource::CloudFrontViewerAddress => {
                    CloudFrontViewerAddress::ip_from_headers(headers)
                }
                SecureClientIpSource::ConnectInfo => extensions
                    .get::<ConnectInfo<SocketAddr>>()
                    .map(|ConnectInfo(addr)| addr.ip())
                    .ok_or_else(|| {
                        "Can't extract `SecureClientIp`, provide `axum::extract::ConnectInfo`"
                            .into()
                    }),
            }
            .map(Self)
        }
    }

    impl<S> FromRequestParts<S> for SecureClientIp
    where
        S: Sync,
    {
        type Rejection = StringRejection;

        async fn from_request_parts(
            parts: &mut Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
            match parts.extensions.get() {
                Some(ip_source) => Ok(Self::from(ip_source, &parts.headers, &parts.extensions)?),
                _ => Err(
                    "Can't extract `SecureClientIp`, add `SecureClientIpSource` into extensions"
                        .into(),
                ),
            }
        }
    }
}

mod insecure {
    use std::{
        marker::Sync,
        net::{IpAddr, SocketAddr},
    };

    use axum::{
        extract::{ConnectInfo, FromRequestParts},
        http::{Extensions, HeaderMap, HeaderValue, StatusCode, request::Parts},
    };

    use crate::basic::{
        CfConnectingIp, CloudFrontViewerAddress, FlyClientIp, Forwarded, MultiIpHeader,
        SingleIpHeader, TrueClientIp, XForwardedFor, XRealIp,
    };

    /// An insecure client IP extractor - no security, but somehow better IP
    /// determination
    ///
    /// This extractor is meant for cases when you'd prefer to **sacrifice
    /// security** for probably statistically **better IP determination**. A
    /// good usage example would be IP-based geolocation if the wrong
    /// location won't be a security issue for your app. But for something
    /// like rate limiting you certainly should use
    /// [`crate::SecureClientIp`] instead.
    ///
    /// Technically it means looking for leftmost IP addresses provided by
    /// forward proxy first, and then look into single IP headers like
    /// `X-Real-Ip`, and then falling back to the
    /// [`axum::extract::ConnectInfo`].
    ///
    /// It returns a 500 error if you forget to provide the `ConnectInfo` with
    /// e.g. [`axum::routing::Router::into_make_service_with_connect_info`]
    ///
    /// Here's a configuration [example][].
    ///
    /// [example]: https://github.com/imbolc/axum-client-ip/blob/main/examples/insecure.rs
    #[derive(Debug, Clone, Copy)]
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
                .or_else(|| CloudFrontViewerAddress::maybe_ip_from_headers(headers))
                .or_else(|| maybe_connect_info(extensions))
                .map(Self)
                .ok_or((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Can't extract `UnsecureClientIp`, provide `axum::extract::ConnectInfo`",
                ))
        }
    }

    impl<S> FromRequestParts<S> for InsecureClientIp
    where
        S: Sync,
    {
        type Rejection = Rejection;

        async fn from_request_parts(
            parts: &mut Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
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
        use axum::{Router, body::Body, http::Request, routing::get};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        use super::InsecureClientIp;

        fn app() -> Router {
            Router::new().route(
                "/",
                get(|InsecureClientIp(ip): InsecureClientIp| async move { ip.to_string() }),
            )
        }

        async fn body_string(body: Body) -> String {
            let bytes = body.collect().await.unwrap().to_bytes();
            String::from_utf8_lossy(&bytes).into()
        }

        #[tokio::test]
        async fn x_forwarded_for() {
            let req = Request::builder()
                .uri("/")
                .header("X-Forwarded-For", "1.1.1.1, 2.2.2.2")
                .body(Body::empty())
                .unwrap();
            let resp = app().oneshot(req).await.unwrap();
            assert_eq!(body_string(resp.into_body()).await, "1.1.1.1");
        }

        #[tokio::test]
        async fn x_real_ip() {
            let req = Request::builder()
                .uri("/")
                .header("X-Real-Ip", "1.2.3.4")
                .body(Body::empty())
                .unwrap();
            let resp = app().oneshot(req).await.unwrap();
            assert_eq!(body_string(resp.into_body()).await, "1.2.3.4");
        }

        #[tokio::test]
        async fn forwarded() {
            let req = Request::builder()
                .uri("/")
                .header("Forwarded", "For=\"[2001:db8:cafe::17]:4711\"")
                .body(Body::empty())
                .unwrap();
            let resp = app().oneshot(req).await.unwrap();
            assert_eq!(body_string(resp.into_body()).await, "2001:db8:cafe::17");
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
            let resp = app().oneshot(req).await.unwrap();
            assert_eq!(body_string(resp.into_body()).await, "1.1.1.1");
        }
    }
}

pub(crate) mod rejection {
    use std::convert::Infallible;

    use axum::{
        http::StatusCode,
        response::{IntoResponse, Response},
    };

    #[derive(Debug)]
    pub struct StringRejection(String);

    pub(crate) type InfallibleRejection = (StatusCode, Infallible);

    impl<T: Into<String>> From<T> for StringRejection {
        fn from(val: T) -> Self {
            Self(val.into())
        }
    }

    impl IntoResponse for StringRejection {
        fn into_response(self) -> Response {
            (StatusCode::INTERNAL_SERVER_ERROR, self.0).into_response()
        }
    }

    impl std::fmt::Display for StringRejection {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl std::error::Error for StringRejection {}
}
