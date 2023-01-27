use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, HeaderMap, StatusCode},
};
use std::convert::Infallible;
use std::net::IpAddr;

pub(crate) const X_REAL_IP: &str = "X-Real-Ip";
pub(crate) const X_FORWARDED_FOR: &str = "X-Forwarded-For";
pub(crate) const FORWARDED: &str = "Forwarded";

/// Extracts a valid IP from `X-Real-Ip` header.
/// Rejects with 500 error if the header is absent or the IP isn't valid
pub struct XRealIp(pub IpAddr);

/// Extracts list of valid IPs from `X-Forwarded-For` header
pub struct XForwardedFor(pub Vec<IpAddr>);

/// Extracts the leftmost IP from `X-Forwarded-For` header.
/// Rejects with 500 error if the header is absent or there's no valid IP
pub struct LeftmostXForwardedFor(pub IpAddr);

/// Extracts the leftmost IP from `X-Forwarded-For` header.
/// Rejects with 500 error if the header is absent or there's no valid IP
pub struct RightmostXForwardedFor(pub IpAddr);

/// Extracts list of valid IPs from `Forwarded` header
pub struct Forwarded(pub Vec<IpAddr>);

/// Extracts the leftmost IP from `Forwarded` header.
/// Rejects with 500 error if the header is absent or there's no valid IP
pub struct LeftmostForwarded(pub IpAddr);

/// Extracts the leftmost IP from `Forwarded` header.
/// Rejects with 500 error if the header is absent or there's no valid IP
pub struct RightmostForwarded(pub IpAddr);

type StringRejection = (StatusCode, String);
type InfallibleRejection = (StatusCode, Infallible);

trait SingleIpHeader {
    const HEADER: &'static str;

    fn ip_from_headers(headers: &HeaderMap) -> Option<IpAddr> {
        headers
            .get(Self::HEADER)
            .and_then(|hv| hv.to_str().ok())
            .and_then(|s| s.parse::<IpAddr>().ok())
    }

    fn rejection() -> StringRejection {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("No `{}` header, or the IP is invalid", Self::HEADER),
        )
    }
}

trait MultiIpHeader {
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

    fn leftmost_ip(headers: &HeaderMap) -> Option<IpAddr> {
        headers
            .get_all(Self::HEADER)
            .iter()
            .filter_map(|hv| hv.to_str().ok())
            .flat_map(Self::ips_from_header_value)
            .next()
    }

    fn rejection() -> StringRejection {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Couldn't find a valid IP in the `{}` header", Self::HEADER),
        )
    }
}

impl SingleIpHeader for XRealIp {
    const HEADER: &'static str = X_REAL_IP;
}

#[async_trait]
impl<S> FromRequestParts<S> for XRealIp
where
    S: Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(
            Self::ip_from_headers(&parts.headers).ok_or_else(Self::rejection)?,
        ))
    }
}

impl MultiIpHeader for XForwardedFor {
    const HEADER: &'static str = X_FORWARDED_FOR;

    fn ips_from_header_value(header_value: &str) -> Vec<IpAddr> {
        header_value
            .split(',')
            .filter_map(|s| s.trim().parse::<IpAddr>().ok())
            .collect()
    }
}

impl MultiIpHeader for Forwarded {
    const HEADER: &'static str = FORWARDED;

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
            XForwardedFor::leftmost_ip(&parts.headers).ok_or_else(XForwardedFor::rejection)?,
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
            *XForwardedFor::ips_from_headers(&parts.headers)
                .last()
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
            Forwarded::leftmost_ip(&parts.headers).ok_or_else(Forwarded::rejection)?,
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
            *Forwarded::ips_from_headers(&parts.headers)
                .last()
                .ok_or_else(Forwarded::rejection)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Forwarded, LeftmostForwarded, LeftmostXForwardedFor, RightmostForwarded,
        RightmostXForwardedFor, XForwardedFor, XRealIp,
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
            .header("X-Forwarded-For", "2.2.2.2")
            .body(Body::empty())
            .unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(body_string(res.into_body()).await, "2.2.2.2");
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
