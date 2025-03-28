//! An example of configuring `ClientIp` using an environment variable
//!
//! Don't forget to set the variable before running, e.g.:
//! ```sh
//! IP_SOURCE=ConnectInfo cargo run --example configurable
//! ```
use std::net::SocketAddr;

use axum::{Router, routing::get};
use axum_client_ip::{ClientIp, ClientIpSource};

#[derive(serde::Deserialize)]
struct Config {
    ip_source: ClientIpSource,
}

async fn handler(ClientIp(ip): ClientIp) -> String {
    ip.to_string()
}

#[tokio::main]
async fn main() {
    let config: Config = envy::from_env().unwrap();

    let app = Router::new()
        .route("/", get(handler))
        // The line you're probably looking for :)
        .layer(config.ip_source.into_extension());

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

    println!("Listening on http://localhost:3000/");
    axum::serve(
        listener,
        // Required for `ClientIpSource::ConnectInfo`
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap()
}
