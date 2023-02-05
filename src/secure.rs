use crate::rudimental::{
    CfConnectingIp, FlyClientIp, Forwarded, MultiIpHeader, SingleIpHeader, StringRejection,
    TrueClientIp, XForwardedFor, XRealIp,
};
use axum::async_trait;
use axum::extract::{ConnectInfo, Extension, FromRequestParts};
use axum::http::request::Parts;
use serde::{Deserialize, Serialize};
use std::{
    marker::Sync,
    net::{IpAddr, SocketAddr},
};

/// A secure client IP extractor - can't be spoofed if configured correctly
///
/// The configuration would include knowing the header the last proxy (the one you own or
/// the one your cloud server provides) is using to store user connection IP.
/// Then you'd need to pass a corresponding [`SecureClientIpSource`] variant into the
/// [`axum::routing::Router::layer`] as an extension. Look at the [example][].
///
/// [example]: https://github.com/imbolc/axum-client-ip/examples/secure.rs
#[derive(Debug)]
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
}

impl SecureClientIpSource {
    /// Wraps `SecureClientIpSource` into the [`axum::extract::Extension`] for passing to
    /// [`axum::routing::Router::layer`]
    pub fn into_extension(self) -> Extension<Self> {
        Extension(self)
    }
}

impl SecureClientIp {
    fn from_parts(
        ip_source: &SecureClientIpSource,
        parts: &Parts,
    ) -> Result<Self, StringRejection> {
        match ip_source {
            SecureClientIpSource::RightmostForwarded => Forwarded::rightmost_ip(&parts.headers),
            SecureClientIpSource::RightmostXForwardedFor => {
                XForwardedFor::rightmost_ip(&parts.headers)
            }
            SecureClientIpSource::XRealIp => XRealIp::ip_from_headers(&parts.headers),
            SecureClientIpSource::FlyClientIp => FlyClientIp::ip_from_headers(&parts.headers),
            SecureClientIpSource::TrueClientIp => TrueClientIp::ip_from_headers(&parts.headers),
            SecureClientIpSource::CfConnectingIp => CfConnectingIp::ip_from_headers(&parts.headers),
            SecureClientIpSource::ConnectInfo => parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(addr)| addr.ip())
                .ok_or_else(|| {
                    "Can't extract `SecureClientIp`, provide `axum::extract::ConnectInfo`".into()
                }),
        }
        .map(Self)
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for SecureClientIp
where
    S: Sync,
{
    type Rejection = StringRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if let Some(ip_source) = parts.extensions.get() {
            Ok(SecureClientIp::from_parts(ip_source, parts)?)
        } else {
            Err("Can't extract `SecureClientIp`, add `SecureClientIpSource` into extensions".into())
        }
    }
}
