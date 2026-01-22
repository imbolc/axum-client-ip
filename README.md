# `axum-client-ip`

[![License](https://img.shields.io/crates/l/axum-client-ip.svg)](https://choosealicense.com/licenses/mit/)
[![Crates.io](https://img.shields.io/crates/v/axum-client-ip.svg)](https://crates.io/crates/axum-client-ip)
[![Docs.rs](https://docs.rs/axum-client-ip/badge.svg)](https://docs.rs/axum-client-ip)

Client IP address extractors for the [Axum] web framework. The crate is just a
thin wrapper around a framework-independent [client-ip] crate.

## V1 breaking changes

- Removed `InsecureClientIp` and related "leftmost" IP logic. The library now
  focuses solely on secure extraction based on trusted headers.
- Renamed `SecureClientIp` to `ClientIp`.
- Renamed `SecureClientIpSource` to `ClientIpSource`.

The changes are triggered by
["rightmost" IP extraction bug](https://github.com/imbolc/axum-client-ip/issues/32).

## Configurable vs specific extractors

There's a configurable [`ClientIp`] extractor you can use to make your
application independent from a proxy it can run behind (if any) and also
separate extractors for each proxy / source header.

| Extractor / `ClientIpSource` Variant | Header Used                 | Typical Proxy / Service                                 |
|--------------------------------------| --------------------------- |---------------------------------------------------------|
| [`CfConnectingIp`]                   | `CF-Connecting-IP`          | Cloudflare                                              |
| [`CloudFrontViewerAddress`]          | `CloudFront-Viewer-Address` | AWS CloudFront                                          |
| [`FlyClientIp`]                      | `Fly-Client-IP`             | Fly.io                                                  |
| [`RightmostForwarded`]               | `Forwarded`                 | Proxies supporting RFC 7239 (extracts rightmost `for=`) |
| [`RightmostXForwardedFor`]           | `X-Forwarded-For`           | Nginx, Apache, HAProxy, CDNs, LBs                       |
| [`TrueClientIp`]                     | `True-Client-IP`            | Cloudflare, Akamai                                      |
| [`XEnvoyExternalAddress`]            | `X-Envoy-External-Address`  | Envoy, Istio                                            |
| [`XRealIp`]                          | `X-Real-Ip`                 | Nginx                                                   |
| [`ConnectInfo`]                      | N/A (uses socket address)   | No proxy, e.g. listening directly to 80 port            |

## Configurable extractor

The configurable extractor assumes initializing [`ClientIpSource`] at runtime
(e.g. with an environment variable). This makes sense when you ship a
pre-compiled binary, people meant to use in different environments. Here's an
initialization [example].

## Specific extractors

Specific extractors don't require runtime initialization, but you'd have to
recompile your binary when you change proxy server.

```rust,no_run
// With the renaming, you have to change only one line when you change proxy
use axum_client_ip::XRealIp as ClientIp;

async fn handler(ClientIp(ip): ClientIp) {
    todo!()
}
```

## Contributing

- please run [.pre-commit.sh] before sending a PR, it will check everything

## License

This project is licensed under the [MIT license][license].

[.pre-commit.sh]:
    https://github.com/imbolc/axum-client-ip/blob/main/.pre-commit.sh
[Axum]: https://github.com/tokio-rs/axum
[client-ip]: https://github.com/imbolc/client-ip
[example]:
    https://github.com/imbolc/axum-client-ip/blob/main/examples/configurable.rs
[license]: https://github.com/imbolc/axum-client-ip/blob/main/LICENSE
