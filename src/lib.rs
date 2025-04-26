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
    http::{HeaderMap, HeaderName, StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

/// An internal helper trait to extract an IP from headers
trait IpExtractor {
    const HEADER_NAME: HeaderName;

    /// Extracts IP from decoded header value. Default implementation assumes
    /// the header value is just a valid IP.
    fn ip_from_header_value(header_value: &str) -> Result<IpAddr, Rejection> {
        header_value
            .trim()
            .parse()
            .map_err(|_| Rejection::MalformedHeaderValue {
                header_name: Self::HEADER_NAME,
                header_value: header_value.to_owned(),
            })
    }

    /// Extracts an IP from headers.
    fn ip_from_headers(headers: &HeaderMap) -> Result<IpAddr, Rejection> {
        let header_value = Self::last_header_value(headers)?;
        Self::ip_from_header_value(header_value)
    }

    /// Returns a decoded value of the last occurring header. Can also be used
    /// for a header occurring only once.
    fn last_header_value(headers: &HeaderMap) -> Result<&str, Rejection> {
        headers
            .get_all(Self::HEADER_NAME)
            .into_iter()
            .next_back()
            .ok_or_else(|| Rejection::AbsentHeader {
                header_name: Self::HEADER_NAME,
            })?
            .to_str()
            .map_err(|_| Rejection::NonAsciiHeaderValue {
                header_name: Self::HEADER_NAME,
            })
    }
}

/// Implements default [`IpExtractor`]
macro_rules! impl_default_ip_extractor {
    ($type:ty, $header:literal) => {
        impl IpExtractor for $type {
            const HEADER_NAME: HeaderName = HeaderName::from_static($header);
        }

        impl<S> FromRequestParts<S> for $type
        where
            S: Sync,
        {
            type Rejection = Rejection;

            async fn from_request_parts(
                parts: &mut Parts,
                _state: &S,
            ) -> Result<Self, Self::Rejection> {
                Self::ip_from_headers(&parts.headers).map(Self)
            }
        }
    };
}

/// Extracts an IP from `CF-Connecting-IP` (Cloudflare) header
#[derive(Debug, Clone, Copy)]
pub struct CfConnectingIp(pub IpAddr);

impl_default_ip_extractor!(CfConnectingIp, "cf-connecting-ip");

/// Extracts an IP from `CloudFront-Viewer-Address` (AWS CloudFront) header
#[derive(Debug, Clone, Copy)]
pub struct CloudFrontViewerAddress(pub IpAddr);

impl IpExtractor for CloudFrontViewerAddress {
    const HEADER_NAME: HeaderName = HeaderName::from_static("cloudfront-viewer-address");

    fn ip_from_header_value(header_value: &str) -> Result<IpAddr, Rejection> {
        // Spec: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/adding-cloudfront-headers.html#cloudfront-headers-viewer-location
        // Note: Both IPv4 and IPv6 addresses (in the specified format) do not contain
        //       non-ascii characters, so no need to handle percent-encoding.
        //
        // CloudFront does not use `[::]:12345` style notation for IPv6 (unfortunately),
        // otherwise parsing via `SocketAddr` would be possible.
        header_value
            .rsplit_once(':')
            .map(|(ip, _port)| ip)
            .ok_or_else(|| Rejection::MalformedHeaderValue {
                header_name: Self::HEADER_NAME,
                header_value: header_value.to_owned(),
            })?
            .parse::<IpAddr>()
            .map_err(|_| Rejection::MalformedHeaderValue {
                header_name: Self::HEADER_NAME,
                header_value: header_value.to_owned(),
            })
    }
}

impl<S> FromRequestParts<S> for CloudFrontViewerAddress
where
    S: Sync,
{
    type Rejection = Rejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Self::ip_from_headers(&parts.headers).map(Self)
    }
}

/// Extracts an IP from `Fly-Client-IP` (Fly.io) header
///
/// When [`FlyClientIp`] extractor is run for health check path,
/// provide required `Fly-Client-IP` header through
/// [`services.http_checks.headers`](https://fly.io/docs/reference/configuration/#services-http_checks)
/// or [`http_service.checks.headers`](https://fly.io/docs/reference/configuration/#services-http_checks)
#[derive(Debug, Clone, Copy)]
pub struct FlyClientIp(pub IpAddr);

impl_default_ip_extractor!(FlyClientIp, "fly-client-ip");

/// Extracts the rightmost IP from `Forwarded` header
#[derive(Debug, Clone, Copy)]
pub struct RightmostForwarded(pub IpAddr);

impl IpExtractor for RightmostForwarded {
    const HEADER_NAME: HeaderName = HeaderName::from_static("forwarded");

    fn ip_from_header_value(header_value: &str) -> Result<IpAddr, Rejection> {
        use forwarded_header_value::{ForwardedHeaderValue, Identifier};

        let stanza = ForwardedHeaderValue::from_forwarded(header_value)
            .map_err(|_| Rejection::MalformedHeaderValue {
                header_name: Self::HEADER_NAME,
                header_value: header_value.to_owned(),
            })?
            .into_iter()
            .last()
            .ok_or_else(|| Rejection::MalformedHeaderValue {
                header_name: Self::HEADER_NAME,
                header_value: header_value.to_owned(),
            })?;

        let forwarded_for = stanza
            .forwarded_for
            .ok_or_else(|| Rejection::ForwardedNoFor {
                header_value: header_value.to_owned(),
            })?;

        match forwarded_for {
            Identifier::SocketAddr(a) => Ok(a.ip()),
            Identifier::IpAddr(ip) => Ok(ip),
            Identifier::String(_) => Err(Rejection::ForwardedObfuscated {
                header_value: header_value.to_owned(),
            }),
            Identifier::Unknown => Err(Rejection::ForwardedUnknown {
                header_value: header_value.to_owned(),
            }),
        }
    }
}

impl<S> FromRequestParts<S> for RightmostForwarded
where
    S: Sync,
{
    type Rejection = Rejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Self::ip_from_headers(&parts.headers).map(Self)
    }
}

/// Extracts the rightmost IP from `X-Forwarded-For` header
#[derive(Debug, Clone, Copy)]
pub struct RightmostXForwardedFor(pub IpAddr);

impl IpExtractor for RightmostXForwardedFor {
    const HEADER_NAME: HeaderName = HeaderName::from_static("x-forwarded-for");

    fn ip_from_header_value(header_value: &str) -> Result<IpAddr, Rejection> {
        header_value
            .split(',')
            .next_back()
            .ok_or_else(|| Rejection::MalformedHeaderValue {
                header_name: Self::HEADER_NAME,
                header_value: header_value.to_owned(),
            })?
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| Rejection::MalformedHeaderValue {
                header_name: Self::HEADER_NAME,
                header_value: header_value.to_owned(),
            })
    }
}

impl<S> FromRequestParts<S> for RightmostXForwardedFor
where
    S: Sync,
{
    type Rejection = Rejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Self::ip_from_headers(&parts.headers).map(Self)
    }
}

/// Extracts an IP from `True-Client-IP` (Akamai, Cloudflare) header
#[derive(Debug, Clone, Copy)]
pub struct TrueClientIp(pub IpAddr);

impl_default_ip_extractor!(TrueClientIp, "true-client-ip");

/// Extracts an IP from `X-Real-Ip` (Nginx) header
#[derive(Debug, Clone, Copy)]
pub struct XRealIp(pub IpAddr);

impl_default_ip_extractor!(XRealIp, "x-real-ip");

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
            "RightmostForwarded" => Self::RightmostForwarded,
            "RightmostXForwardedFor" => Self::RightmostXForwardedFor,
            "XRealIp" => Self::XRealIp,
            "FlyClientIp" => Self::FlyClientIp,
            "TrueClientIp" => Self::TrueClientIp,
            "CfConnectingIp" => Self::CfConnectingIp,
            "ConnectInfo" => Self::ConnectInfo,
            "CloudFrontViewerAddress" => Self::CloudFrontViewerAddress,
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
    use std::net::IpAddr;

    use axum::{
        Router,
        body::Body,
        http::{HeaderMap, HeaderName, Request, StatusCode},
        routing::get,
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::{
        CfConnectingIp, FlyClientIp, RightmostForwarded, RightmostXForwardedFor, TrueClientIp,
        XRealIp,
    };
    use crate::{CloudFrontViewerAddress, IpExtractor, Rejection};

    const VALID_IPV4: &str = "1.2.3.4";
    const VALID_IPV6: &str = "1:23:4567:89ab:c:d:e:f";

    async fn body_to_string(body: Body) -> String {
        let bytes = body.collect().await.unwrap().to_bytes();
        String::from_utf8_lossy(&bytes).into()
    }

    fn headers<'a>(items: impl IntoIterator<Item = (&'a str, &'a str)>) -> HeaderMap {
        HeaderMap::from_iter(
            items
                .into_iter()
                .map(|(name, value)| (name.parse().unwrap(), value.parse().unwrap())),
        )
    }

    #[tokio::test]
    async fn cf_connecting_ip() {
        let header = "cf-connecting-ip";

        assert_eq!(
            CfConnectingIp::ip_from_headers(&headers([])).unwrap_err(),
            Rejection::AbsentHeader {
                header_name: HeaderName::from_static(header)
            }
        );
        assert_eq!(
            CfConnectingIp::ip_from_headers(&headers([(header, "ы")])).unwrap_err(),
            Rejection::NonAsciiHeaderValue {
                header_name: HeaderName::from_static(header)
            }
        );
        assert_eq!(
            CfConnectingIp::ip_from_headers(&headers([(header, "foo")])).unwrap_err(),
            Rejection::MalformedHeaderValue {
                header_name: HeaderName::from_static(header),
                header_value: "foo".into(),
            }
        );

        assert_eq!(
            CfConnectingIp::ip_from_headers(&headers([(header, VALID_IPV4)])).unwrap(),
            VALID_IPV4.parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            CfConnectingIp::ip_from_headers(&headers([(header, VALID_IPV6)])).unwrap(),
            VALID_IPV6.parse::<IpAddr>().unwrap()
        );

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

        assert_eq!(
            CloudFrontViewerAddress::ip_from_headers(&headers([])).unwrap_err(),
            Rejection::AbsentHeader {
                header_name: HeaderName::from_static(header)
            }
        );
        assert_eq!(
            CloudFrontViewerAddress::ip_from_headers(&headers([(header, "ы")])).unwrap_err(),
            Rejection::NonAsciiHeaderValue {
                header_name: HeaderName::from_static(header)
            }
        );
        assert_eq!(
            CloudFrontViewerAddress::ip_from_headers(&headers([(header, VALID_IPV4)])).unwrap_err(),
            Rejection::MalformedHeaderValue {
                header_name: HeaderName::from_static(header),
                header_value: VALID_IPV4.into(),
            }
        );
        assert_eq!(
            CloudFrontViewerAddress::ip_from_headers(&headers([(header, "foo:8000")])).unwrap_err(),
            Rejection::MalformedHeaderValue {
                header_name: HeaderName::from_static(header),
                header_value: "foo:8000".into(),
            }
        );

        let valid_header_value_v4 = format!("{VALID_IPV4}:8000");
        let valid_header_value_v6 = format!("{VALID_IPV6}:8000");
        assert_eq!(
            CloudFrontViewerAddress::ip_from_headers(&headers([(
                header,
                valid_header_value_v4.as_ref()
            )]))
            .unwrap(),
            VALID_IPV4.parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            CloudFrontViewerAddress::ip_from_headers(&headers([(
                header,
                valid_header_value_v6.as_ref()
            )]))
            .unwrap(),
            VALID_IPV6.parse::<IpAddr>().unwrap()
        );

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

        assert_eq!(
            FlyClientIp::ip_from_headers(&headers([])).unwrap_err(),
            Rejection::AbsentHeader {
                header_name: HeaderName::from_static(header)
            }
        );
        assert_eq!(
            FlyClientIp::ip_from_headers(&headers([(header, "ы")])).unwrap_err(),
            Rejection::NonAsciiHeaderValue {
                header_name: HeaderName::from_static(header)
            }
        );
        assert_eq!(
            FlyClientIp::ip_from_headers(&headers([(header, "foo")])).unwrap_err(),
            Rejection::MalformedHeaderValue {
                header_name: HeaderName::from_static(header),
                header_value: "foo".into(),
            }
        );

        assert_eq!(
            FlyClientIp::ip_from_headers(&headers([(header, VALID_IPV4)])).unwrap(),
            VALID_IPV4.parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            FlyClientIp::ip_from_headers(&headers([(header, VALID_IPV6)])).unwrap(),
            VALID_IPV6.parse::<IpAddr>().unwrap()
        );

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

    #[tokio::test]
    async fn rightmost_forwarded() {
        let header = "forwarded";

        assert_eq!(
            RightmostForwarded::ip_from_headers(&headers([])).unwrap_err(),
            Rejection::AbsentHeader {
                header_name: HeaderName::from_static(header)
            }
        );
        assert_eq!(
            RightmostForwarded::ip_from_headers(&headers([(header, "ы")])).unwrap_err(),
            Rejection::NonAsciiHeaderValue {
                header_name: HeaderName::from_static(header)
            }
        );
        assert_eq!(
            RightmostForwarded::ip_from_headers(&headers([(header, "foo")])).unwrap_err(),
            Rejection::MalformedHeaderValue {
                header_name: HeaderName::from_static(header),
                header_value: "foo".into(),
            }
        );
        assert_eq!(
            RightmostForwarded::ip_from_headers(&headers([
                (header, format!("for={VALID_IPV4}").as_ref()),
                (header, "proto=http"),
            ]))
            .unwrap_err(),
            Rejection::ForwardedNoFor {
                header_value: "proto=http".into(),
            }
        );
        assert_eq!(
            RightmostForwarded::ip_from_headers(&headers([(header, "for=unknown")])).unwrap_err(),
            Rejection::ForwardedUnknown {
                header_value: "for=unknown".into(),
            }
        );
        assert_eq!(
            RightmostForwarded::ip_from_headers(&headers([(header, "for=_foo")])).unwrap_err(),
            Rejection::ForwardedObfuscated {
                header_value: "for=_foo".into(),
            }
        );

        assert_eq!(
            RightmostForwarded::ip_from_headers(&headers([
                (header, "proto=http"),
                (header, format!("for={VALID_IPV4};proto=http").as_ref()),
            ]))
            .unwrap(),
            VALID_IPV4.parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            RightmostForwarded::ip_from_headers(&headers([(
                header,
                format!("for={VALID_IPV4}:8000").as_ref()
            ),]))
            .unwrap(),
            VALID_IPV4.parse::<IpAddr>().unwrap()
        );

        assert_eq!(
            RightmostForwarded::ip_from_headers(&headers([(
                header,
                format!("for={VALID_IPV6}").as_ref()
            ),]))
            .unwrap(),
            VALID_IPV6.parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            RightmostForwarded::ip_from_headers(&headers([(
                header,
                format!("for=[{VALID_IPV6}]:8000").as_ref()
            ),]))
            .unwrap(),
            VALID_IPV6.parse::<IpAddr>().unwrap()
        );

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
        let header = "x-forwarded-for";

        assert_eq!(
            RightmostXForwardedFor::ip_from_headers(&headers([])).unwrap_err(),
            Rejection::AbsentHeader {
                header_name: HeaderName::from_static(header)
            }
        );
        assert_eq!(
            RightmostXForwardedFor::ip_from_headers(&headers([(header, "ы")])).unwrap_err(),
            Rejection::NonAsciiHeaderValue {
                header_name: HeaderName::from_static(header)
            }
        );
        assert_eq!(
            RightmostXForwardedFor::ip_from_headers(&headers([(header, "1.2.3.4,foo")]))
                .unwrap_err(),
            Rejection::MalformedHeaderValue {
                header_name: HeaderName::from_static(header),
                header_value: "1.2.3.4,foo".into(),
            }
        );

        assert_eq!(
            RightmostXForwardedFor::ip_from_headers(&headers([(
                header,
                format!("foo,{VALID_IPV4}").as_ref()
            )]))
            .unwrap(),
            VALID_IPV4.parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            RightmostXForwardedFor::ip_from_headers(&headers([(header, VALID_IPV6)])).unwrap(),
            VALID_IPV6.parse::<IpAddr>().unwrap()
        );

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

        assert_eq!(
            TrueClientIp::ip_from_headers(&headers([])).unwrap_err(),
            Rejection::AbsentHeader {
                header_name: HeaderName::from_static(header)
            }
        );
        assert_eq!(
            TrueClientIp::ip_from_headers(&headers([(header, "ы")])).unwrap_err(),
            Rejection::NonAsciiHeaderValue {
                header_name: HeaderName::from_static(header)
            }
        );
        assert_eq!(
            TrueClientIp::ip_from_headers(&headers([(header, "foo")])).unwrap_err(),
            Rejection::MalformedHeaderValue {
                header_name: HeaderName::from_static(header),
                header_value: "foo".into(),
            }
        );

        assert_eq!(
            TrueClientIp::ip_from_headers(&headers([(header, VALID_IPV4)])).unwrap(),
            VALID_IPV4.parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            TrueClientIp::ip_from_headers(&headers([(header, VALID_IPV6)])).unwrap(),
            VALID_IPV6.parse::<IpAddr>().unwrap()
        );

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

        assert_eq!(
            XRealIp::ip_from_headers(&headers([])).unwrap_err(),
            Rejection::AbsentHeader {
                header_name: HeaderName::from_static(header)
            }
        );
        assert_eq!(
            XRealIp::ip_from_headers(&headers([(header, "ы")])).unwrap_err(),
            Rejection::NonAsciiHeaderValue {
                header_name: HeaderName::from_static(header)
            }
        );
        assert_eq!(
            XRealIp::ip_from_headers(&headers([(header, "foo")])).unwrap_err(),
            Rejection::MalformedHeaderValue {
                header_name: HeaderName::from_static(header),
                header_value: "foo".into(),
            }
        );

        assert_eq!(
            XRealIp::ip_from_headers(&headers([(header, VALID_IPV4)])).unwrap(),
            VALID_IPV4.parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            XRealIp::ip_from_headers(&headers([(header, VALID_IPV6)])).unwrap(),
            VALID_IPV6.parse::<IpAddr>().unwrap()
        );

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
