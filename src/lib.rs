#![doc = include_str!("../README.md")]
use std::{
    error::Error,
    fmt,
    marker::Sync,
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use axum::{
    extract::{ConnectInfo, Extension, FromRequestParts},
    http::{HeaderName, StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

/// Defines an extractor
macro_rules! define_extractor {
    (
        $(#[$meta:meta])*
        $newtype:ident,
        $extractor:path
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy)]
        pub struct $newtype(pub std::net::IpAddr);

        impl $newtype {
            fn ip_from_headers(headers: &axum::http::HeaderMap) -> Result<std::net::IpAddr, Rejection> {
                Ok($extractor(&headers)?)
            }
        }

        impl<S> axum::extract::FromRequestParts<S> for $newtype
        where
            S: Sync,
        {
            type Rejection = Rejection; // Replace with your actual Rejection type if different

            async fn from_request_parts(
                parts: &mut axum::http::request::Parts, // Or your specific Parts type
                _state: &S,
            ) -> Result<Self, Self::Rejection> {
                Self::ip_from_headers(&parts.headers).map(Self)
            }
        }
    };
}

define_extractor!(
    /// Extracts an IP from `CF-Connecting-IP` (Cloudflare) header
    CfConnectingIp,
    client_ip::cf_connecting_ip
);

define_extractor!(
    /// Extracts an IP from `CloudFront-Viewer-Address` (AWS CloudFront) header
    CloudFrontViewerAddress,
    client_ip::cloudfront_viewer_address
);

define_extractor!(
    /// Extracts an IP from `Fly-Client-IP` (Fly.io) header
    ///
    /// When [`FlyClientIp`] extractor is run for health check path,
    /// provide required `Fly-Client-IP` header through
    /// [`services.http_checks.headers`](https://fly.io/docs/reference/configuration/#services-http_checks)
    /// or [`http_service.checks.headers`](https://fly.io/docs/reference/configuration/#services-http_checks)
    FlyClientIp,
    client_ip::fly_client_ip
);

#[cfg(feature = "forwarded-header")]
define_extractor!(
    /// Extracts the rightmost IP from `Forwarded` header
    RightmostForwarded,
    client_ip::rightmost_forwarded
);

define_extractor!(
    /// Extracts the rightmost IP from `X-Forwarded-For` header
    RightmostXForwardedFor,
    client_ip::rightmost_x_forwarded_for
);

define_extractor!(
    /// Extracts an IP from `True-Client-IP` (Akamai, Cloudflare) header
    TrueClientIp,
    client_ip::true_client_ip
);

define_extractor!(
    /// Extracts an IP from `X-Real-Ip` (Nginx) header
    XRealIp,
    client_ip::x_real_ip
);

/// Client IP extractor with configurable source
///
/// The configuration would include knowing the header the last proxy (the
/// one you own or the one your cloud server provides) is using to store
/// user connection IP. Then you'd need to pass a corresponding
/// [`ClientIpSource`] variant into the [`axum::routing::Router::layer`] as
/// an extension. Look at the [example][].
///
/// [example]: https://github.com/imbolc/axum-client-ip/blob/main/examples/integration.rs
#[derive(Debug, Clone, Copy)]
pub struct ClientIp(pub IpAddr);

/// [`ClientIp`] source configuration
#[non_exhaustive]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ClientIpSource {
    /// IP from the `CF-Connecting-IP` header
    CfConnectingIp,
    /// IP from the `CloudFront-Viewer-Address` header
    CloudFrontViewerAddress,
    /// IP from the [`axum::extract::ConnectInfo`]
    ConnectInfo,
    /// IP from the `Fly-Client-IP` header
    FlyClientIp,
    #[cfg(feature = "forwarded-header")]
    /// Rightmost IP from the `Forwarded` header
    RightmostForwarded,
    /// Rightmost IP from the `X-Forwarded-For` header
    RightmostXForwardedFor,
    /// IP from the `True-Client-IP` header
    TrueClientIp,
    /// IP from the `X-Real-Ip` header
    XRealIp,
}

impl ClientIpSource {
    /// Wraps [`ClientIpSource`] into the [`axum::extract::Extension`]
    /// for passing to [`axum::routing::Router::layer`]
    pub const fn into_extension(self) -> Extension<Self> {
        Extension(self)
    }
}

/// Invalid [`ClientIpSource`]
#[derive(Debug)]
pub struct ParseClientIpSourceError(String);

impl fmt::Display for ParseClientIpSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid ClientIpSource value {}", self.0)
    }
}

impl Error for ParseClientIpSourceError {}

impl FromStr for ClientIpSource {
    type Err = ParseClientIpSourceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "CfConnectingIp" => Self::CfConnectingIp,
            "CloudFrontViewerAddress" => Self::CloudFrontViewerAddress,
            "ConnectInfo" => Self::ConnectInfo,
            "FlyClientIp" => Self::FlyClientIp,
            #[cfg(feature = "forwarded-header")]
            "RightmostForwarded" => Self::RightmostForwarded,
            "RightmostXForwardedFor" => Self::RightmostXForwardedFor,
            "TrueClientIp" => Self::TrueClientIp,
            "XRealIp" => Self::XRealIp,
            _ => return Err(ParseClientIpSourceError(s.to_string())),
        })
    }
}

impl<S> FromRequestParts<S> for ClientIp
where
    S: Sync,
{
    type Rejection = Rejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let Some(ip_source) = parts.extensions.get() else {
            return Err(Rejection::NoClientIpSource);
        };

        match ip_source {
            ClientIpSource::CfConnectingIp => CfConnectingIp::ip_from_headers(&parts.headers),
            ClientIpSource::CloudFrontViewerAddress => {
                CloudFrontViewerAddress::ip_from_headers(&parts.headers)
            }
            ClientIpSource::ConnectInfo => parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(addr)| addr.ip())
                .ok_or_else(|| Rejection::NoConnectInfo),
            ClientIpSource::FlyClientIp => FlyClientIp::ip_from_headers(&parts.headers),
            #[cfg(feature = "forwarded-header")]
            ClientIpSource::RightmostForwarded => {
                RightmostForwarded::ip_from_headers(&parts.headers)
            }
            ClientIpSource::RightmostXForwardedFor => {
                RightmostXForwardedFor::ip_from_headers(&parts.headers)
            }
            ClientIpSource::TrueClientIp => TrueClientIp::ip_from_headers(&parts.headers),
            ClientIpSource::XRealIp => XRealIp::ip_from_headers(&parts.headers),
        }
        .map(Self)
    }
}

/// Rejection type for IP extractors
#[non_exhaustive]
#[derive(Debug, PartialEq)]
pub enum Rejection {
    /// No [`axum::extract::ConnectInfo`] in extensions
    NoConnectInfo,
    /// No [`ClientIpSource`] in extensions
    NoClientIpSource,
    /// The IP-related header is missing
    AbsentHeader {
        /// Header name
        header_name: HeaderName,
    },
    /// Header value contains not only visible ASCII characters
    NonAsciiHeaderValue {
        /// Header name
        header_name: HeaderName,
    },
    /// Header value has an unexpected format
    MalformedHeaderValue {
        /// Header name
        header_name: HeaderName,
        /// Header value
        header_value: String,
    },
    /// Multiple occurrences of a header required to occur only once found
    ///
    /// According to the HTTP/1.1 specification (RFC 7230, Section 3.2.2):
    /// > A sender MUST NOT generate multiple header fields with the same
    /// > field name in a message unless either the entire field value for
    /// > that header field is defined as a comma-separated list ...
    SingleHeaderRequired {
        /// Header name
        header_name: HeaderName,
    },
    /// Forwarded header doesn't contain `for` directive
    ForwardedNoFor {
        /// Header value
        header_value: String,
    },
    /// RFC 7239 allows to [obfuscate IPs](https://www.rfc-editor.org/rfc/rfc7239.html#section-6.3)
    ForwardedObfuscated {
        /// Header value
        header_value: String,
    },
    /// RFC 7239 allows [unknown identifiers](https://www.rfc-editor.org/rfc/rfc7239.html#section-6.2)
    ForwardedUnknown {
        /// Header value
        header_value: String,
    },
}

impl From<client_ip::Error> for Rejection {
    fn from(value: client_ip::Error) -> Self {
        match value {
            client_ip::Error::AbsentHeader { header_name } => {
                Rejection::AbsentHeader { header_name }
            }
            client_ip::Error::NonAsciiHeaderValue { header_name } => {
                Rejection::NonAsciiHeaderValue { header_name }
            }
            client_ip::Error::MalformedHeaderValue {
                header_name,
                header_value,
            } => Rejection::MalformedHeaderValue {
                header_name,
                header_value,
            },
            client_ip::Error::SingleHeaderRequired { header_name } => {
                Rejection::SingleHeaderRequired { header_name }
            }
            #[cfg(feature = "forwarded-header")]
            client_ip::Error::ForwardedNoFor { header_value } => {
                Rejection::ForwardedNoFor { header_value }
            }
            #[cfg(feature = "forwarded-header")]
            client_ip::Error::ForwardedObfuscated { header_value } => {
                Rejection::ForwardedObfuscated { header_value }
            }
            #[cfg(feature = "forwarded-header")]
            client_ip::Error::ForwardedUnknown { header_value } => {
                Rejection::ForwardedUnknown { header_value }
            }
        }
    }
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rejection::NoConnectInfo => {
                write!(f, "Add `axum::extract::ConnectInfo` to request extensions")
            }
            Rejection::NoClientIpSource => write!(
                f,
                "Add `axum_client_ip::ClientIpSource` to request extensions"
            ),
            Rejection::AbsentHeader { header_name } => {
                write!(f, "Missing required header: {header_name}")
            }
            Rejection::SingleHeaderRequired { header_name } => write!(
                f,
                "Multiple occurrences of the header aren't allowed: {header_name}"
            ),
            Rejection::NonAsciiHeaderValue { header_name } => write!(
                f,
                "Header value contains non-ASCII characters: {header_name}",
            ),
            Rejection::MalformedHeaderValue {
                header_name,
                header_value,
            } => write!(
                f,
                "Malformed header value for `{header_name}`: {header_value}",
            ),
            Rejection::ForwardedNoFor { header_value } => write!(
                f,
                "`Forwarded` header missing `for` directive: {header_value}",
            ),
            Rejection::ForwardedObfuscated { header_value } => write!(
                f,
                "`Forwarded` header contains obfuscated IP: {header_value}",
            ),
            Rejection::ForwardedUnknown { header_value } => write!(
                f,
                "`Forwarded` header contains unknown identifier: {header_value}",
            ),
        }
    }
}

impl std::error::Error for Rejection {}

impl IntoResponse for Rejection {
    fn into_response(self) -> Response {
        let request_issue = (StatusCode::BAD_REQUEST, "400 Bad Request");
        let proxy_issue = (
            StatusCode::INTERNAL_SERVER_ERROR,
            "500 Proxy Server Misconfiguration",
        );
        let axum_issue = (
            StatusCode::INTERNAL_SERVER_ERROR,
            "500 Axum Misconfiguration",
        );

        let (code, title) = match self {
            Self::NoConnectInfo => axum_issue,
            Self::NoClientIpSource => axum_issue,
            Self::AbsentHeader { .. } => proxy_issue,
            Self::NonAsciiHeaderValue { .. } => proxy_issue,
            Self::MalformedHeaderValue { .. } => proxy_issue,
            Self::SingleHeaderRequired { .. } => proxy_issue,
            Self::ForwardedNoFor { .. } => proxy_issue,
            Self::ForwardedObfuscated { .. } => proxy_issue,
            Self::ForwardedUnknown { .. } => request_issue,
        };

        let footer = "(the request is rejected by axum-client-ip)";
        let text = format!("{title}\n\n{self}\n\n{footer}");
        (code, text).into_response()
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

    #[cfg(feature = "forwarded-header")]
    use super::RightmostForwarded;
    use super::{CfConnectingIp, FlyClientIp, RightmostXForwardedFor, TrueClientIp, XRealIp};
    use crate::CloudFrontViewerAddress;

    const VALID_IPV4: &str = "1.2.3.4";
    const VALID_IPV6: &str = "1:23:4567:89ab:c:d:e:f";

    async fn body_to_string(body: Body) -> String {
        let bytes = body.collect().await.unwrap().to_bytes();
        String::from_utf8_lossy(&bytes).into()
    }

    #[tokio::test]
    async fn cf_connecting_ip() {
        let header = "cf-connecting-ip";

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
            .header(header, VALID_IPV4)
            .body(Body::empty())
            .unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(body_to_string(resp.into_body()).await, VALID_IPV4);

        let req = Request::builder()
            .uri("/")
            .header(header, VALID_IPV6)
            .body(Body::empty())
            .unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(body_to_string(resp.into_body()).await, VALID_IPV6);
    }

    #[tokio::test]
    async fn cloudfront_viewer_address() {
        let header = "cloudfront-viewer-address";

        let valid_header_value_v4 = format!("{VALID_IPV4}:8000");
        let valid_header_value_v6 = format!("{VALID_IPV6}:8000");

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
            .header(header, &valid_header_value_v4)
            .body(Body::empty())
            .unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(body_to_string(resp.into_body()).await, VALID_IPV4);

        let req = Request::builder()
            .uri("/")
            .header(header, &valid_header_value_v6)
            .body(Body::empty())
            .unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(body_to_string(resp.into_body()).await, VALID_IPV6);
    }

    #[tokio::test]
    async fn fly_client_ip() {
        let header = "fly-client-ip";

        fn app() -> Router {
            Router::new().route("/", get(|ip: FlyClientIp| async move { ip.0.to_string() }))
        }

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let req = Request::builder()
            .uri("/")
            .header(header, VALID_IPV4)
            .body(Body::empty())
            .unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(body_to_string(resp.into_body()).await, VALID_IPV4);

        let req = Request::builder()
            .uri("/")
            .header(header, VALID_IPV6)
            .body(Body::empty())
            .unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(body_to_string(resp.into_body()).await, VALID_IPV6);
    }

    #[cfg(feature = "forwarded-header")]
    #[tokio::test]
    async fn rightmost_forwarded() {
        let header = "forwarded";

        fn app() -> Router {
            Router::new().route(
                "/",
                get(|ip: RightmostForwarded| async move { ip.0.to_string() }),
            )
        }

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let req = Request::builder()
            .uri("/")
            .header(header, format!("for=[{VALID_IPV6}]:8000"))
            .body(Body::empty())
            .unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(body_to_string(resp.into_body()).await, VALID_IPV6);

        let req = Request::builder()
            .uri("/")
            .header("Forwarded", r#"for="_mdn""#)
            .header("Forwarded", r#"For="[2001:db8:cafe::17]:4711""#)
            .header("Forwarded", r#"for=192.0.2.60;proto=http;by=203.0.113.43"#)
            .body(Body::empty())
            .unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(body_to_string(resp.into_body()).await, "192.0.2.60");
    }

    #[tokio::test]
    async fn rightmost_x_forwarded_for() {
        fn app() -> Router {
            Router::new().route(
                "/",
                get(|ip: RightmostXForwardedFor| async move { ip.0.to_string() }),
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
            .header("X-Forwarded-For", format!("2.2.2.2, {VALID_IPV4}"))
            .body(Body::empty())
            .unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(body_to_string(resp.into_body()).await, VALID_IPV4);
    }

    #[tokio::test]
    async fn true_client_ip() {
        let header = "true-client-ip";

        fn app() -> Router {
            Router::new().route("/", get(|ip: TrueClientIp| async move { ip.0.to_string() }))
        }

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let req = Request::builder()
            .uri("/")
            .header(header, VALID_IPV4)
            .body(Body::empty())
            .unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(body_to_string(resp.into_body()).await, VALID_IPV4);

        let req = Request::builder()
            .uri("/")
            .header(header, VALID_IPV6)
            .body(Body::empty())
            .unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(body_to_string(resp.into_body()).await, VALID_IPV6);
    }

    #[tokio::test]
    async fn x_real_ip() {
        let header = "x-real-ip";

        fn app() -> Router {
            Router::new().route("/", get(|ip: XRealIp| async move { ip.0.to_string() }))
        }

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let req = Request::builder()
            .uri("/")
            .header(header, VALID_IPV4)
            .body(Body::empty())
            .unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(body_to_string(resp.into_body()).await, VALID_IPV4);

        let req = Request::builder()
            .uri("/")
            .header(header, VALID_IPV6)
            .body(Body::empty())
            .unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(body_to_string(resp.into_body()).await, VALID_IPV6);
    }
}
