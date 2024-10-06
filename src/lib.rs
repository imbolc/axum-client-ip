#![doc = include_str!("../README.md")]

mod insecure;
mod rudimental;
mod secure;
pub use insecure::InsecureClientIp;
pub use rudimental::{
    CfConnectingIp, CloudFrontViewerAddress, FlyClientIp, Forwarded, LeftmostForwarded,
    LeftmostXForwardedFor, RightmostForwarded, RightmostXForwardedFor, TrueClientIp, XForwardedFor,
    XRealIp,
};
pub use secure::{SecureClientIp, SecureClientIpSource};
pub(crate) mod rejection;
