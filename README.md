# `axum-client-ip`

[![License](https://img.shields.io/crates/l/axum-client-ip.svg)](https://choosealicense.com/licenses/mit/)
[![Crates.io](https://img.shields.io/crates/v/axum-client-ip.svg)](https://crates.io/crates/axum-client-ip)
[![Docs.rs](https://docs.rs/axum-client-ip/badge.svg)](https://docs.rs/axum-client-ip)

Client IP address extractors for Axum

## Why different extractors?

There are two distinct use cases for client IP which should be treated
differently:

1. You can't tolerate the possibility of spoofing (you're working on rate
   limiting, spam protection, etc). In this case, you should use
   [`SecureClientIp`] or an extractor for a particular header.
2. You can trade potential spoofing for a statistically better IP
   determination. E.g. you use the IP for geolocation when the correctness
   of the location isn't critical for your app. For something like this, you
   can use [`InsecureClientIp`].

For a deep dive into the trade-off refer to this Adam Pritchard's
[article](https://adam-p.ca/blog/2022/03/x-forwarded-for/)

## `SecureClientIp` vs specific header extractors

Apart from [`SecureClientIp`] there are concrete
[`CfConnectingIp`],
[`CloudFrontViewerAddress`],
[`FlyClientIp`],
[`Forwarded`],
[`RightmostForwarded`],
[`RightmostXForwardedFor`],
[`TrueClientIp`],
[`XForwardedFor`] and
[`XRealIp`]
secure extractors. You can use them directly if your code assumes a specific
proxy configuration.

They work the same way - by extracting IP from the specified header you
control. The only difference is in the target header specification. With
`SecureClientIp` you can specify the header at runtime, so you can use e.g.
environment variable for this setting (look at the implementation
[example][secure-example]). While with specific extractors you'd need to
recompile your code if you'd like to change the target header (e.g. you're
moving to another cloud provider). To mitigate this change you can create a
type alias e.g. `type InsecureIp = XRealIp` and use it in your handlers,
then the change will affect only one line.

## Usage

```rust,no_run
use axum::{routing::get, Router};
use axum_client_ip::{InsecureClientIp, SecureClientIp, SecureClientIpSource};
use std::net::SocketAddr;

async fn handler(insecure_ip: InsecureClientIp, secure_ip: SecureClientIp) -> String {
    format!("{insecure_ip:?} {secure_ip:?}")
}

#[tokio::main]
async fn main() {
    async fn handler(insecure_ip: InsecureClientIp, secure_ip: SecureClientIp) -> String {
        format!("{insecure_ip:?} {secure_ip:?}")
    }

    let app = Router::new().route("/", get(handler))
        .layer(SecureClientIpSource::ConnectInfo.into_extension());

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(
        listener,
        // Don't forget to add `ConnectInfo` if you aren't behind a proxy
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap()
}
```


## A common issue with Axum extractors

The most often issue with this extractor is using it after one consuming
body e.g. [`axum::extract::Json`].
To fix this rearrange extractors in your handler definition moving body
consumption to the end, see [details][extractors-order].


## Contributing

- please run [.pre-commit.sh] before sending a PR, it will check everything


## License

This project is licensed under the [MIT license](LICENSE).

[.pre-commit.sh]: https://github.com/imbolc/axum-client-ip/blob/main/pre-commit.sh
[extractors-order]: https://docs.rs/axum/latest/axum/extract/index.html#the-order-of-extractors
[secure-example]: https://github.com/imbolc/axum-client-ip/blob/main/examples/secure.rs
