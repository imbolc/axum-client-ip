//! An example of configuring `SecureClientIp` using an env variable
//! Don't forget set the variable before running e.g.: `IP_SOURCE=ConnectInfo
//! cargo run --example secure`
use std::net::SocketAddr;

use axum::{routing::get, Router};
use axum_client_ip::{SecureClientIp, SecureClientIpSource};

#[derive(serde::Deserialize)]
struct Config {
    ip_source: SecureClientIpSource,
}

async fn handler(SecureClientIp(ip): SecureClientIp) -> String {
    ip.to_string()
}

#[tokio::main]
async fn main() {
    let config: Config = envy::from_env().unwrap();

    let app = Router::new()
        .route("/", get(handler))
        // the line you're probably looking for :)
        .layer(config.ip_source.into_extension());

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

    println!("Listening on http://localhost:3000/");
    axum::serve(
        listener,
        // Don't forget to add `ConnectInfo`
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap()
}
