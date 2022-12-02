[![License](https://img.shields.io/crates/l/axum-client-ip.svg)](https://choosealicense.com/licenses/mit/)
[![Crates.io](https://img.shields.io/crates/v/axum-client-ip.svg)](https://crates.io/crates/axum-client-ip)
[![Docs.rs](https://docs.rs/axum-client-ip/badge.svg)](https://docs.rs/axum-client-ip)

# axum-client-ip

<!-- cargo-sync-readme start -->

A client IP address extractor for Axum

It sequentially looks for an IP in:

- `x-forwarded-for` header (de-facto standard)
- `x-real-ip` header
- `forwarded` header (new standard)
- [`axum::extract::ConnectInfo`][connect-info] (if not behind proxy)

## Usage

```rust,no_run
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

<!-- cargo-sync-readme end -->

## Contributing

We appreciate all kinds of contributions, thank you!


### Note on README

Most of the readme is automatically copied from the crate documentation by [cargo-sync-readme][].
This way the readme is always in sync with the docs and examples are tested.

So if you find a part of the readme you'd like to change between `<!-- cargo-sync-readme start -->`
and `<!-- cargo-sync-readme end -->` markers, don't edit `README.md` directly, but rather change
the documentation on top of `src/lib.rs` and then synchronize the readme with:
```bash
cargo sync-readme
```
(make sure the cargo command is installed):
```bash
cargo install cargo-sync-readme
```

If you have [rusty-hook] installed the changes will apply automatically on commit.


## License

This project is licensed under the [MIT license](LICENSE).

[cargo-sync-readme]: https://github.com/phaazon/cargo-sync-readme
[rusty-hook]: https://github.com/swellaby/rusty-hook
