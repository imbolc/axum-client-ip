[![License](https://img.shields.io/crates/l/axum-client-ip.svg)](https://choosealicense.com/licenses/mit/)
[![Crates.io](https://img.shields.io/crates/v/axum-client-ip.svg)](https://crates.io/crates/axum-client-ip)
[![Docs.rs](https://docs.rs/axum-client-ip/badge.svg)](https://docs.rs/axum-client-ip)

# axum-client-ip

A client IP address extractor for Axum

It sequentially looks for an IP in:

- `x-forwarded-for` header (de-facto standard)
- `x-real-ip` header
- `forwarded` header (new standard)
- [`axum::extract::ConnectInfo`][connect-info] (if not behind proxy)

### Usage

```rust
use axum::{routing::get, Router};
use axum_client_ip::ClientIp;
use std::net::SocketAddr;

pub async fn handler(ClientIp(ip): ClientIp) -> String {
    ip.to_string()
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/", get(handler));

    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(
            // Don't forget to add `ConnetInfo` if you aren't behind a proxy
            app.into_make_service_with_connect_info::<SocketAddr>()
        )
        .await
        .unwrap()
}
```

[connect-info]: https://docs.rs/axum/latest/axum/extract/struct.ConnectInfo.html

## Contributing

We appreciate all kinds of contributions, thank you!

### Note on README

The `README.md` file isn't meant to be changed directly. It instead generated from the crate's docs
by the [cargo-readme] command:

* Install the command if you don't have it: `cargo install cargo-readme`
* Change the crate-level docs in `src/lib.rs`, or wrapping text in `README.tpl`
* Apply the changes: `cargo readme > README.md`

If you have [rusty-hook] installed the changes will apply automatically on commit.

## License

This project is licensed under the [MIT license](LICENSE).

[cargo-readme]: https://github.com/livioribeiro/cargo-readme
[rusty-hook]: https://github.com/swellaby/rusty-hook
