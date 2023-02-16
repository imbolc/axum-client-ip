//! An example of configuring `MaybeSecureClientIp` using an env variable
//! Don't forget set the variable before running e.g.: `IP_SOURCE=ConnectInfo cargo run --example maybe-secure`
use axum::{routing::get, Router};
use axum_client_ip::{MaybeSecureClientIp, SecureClientIpSource};
use std::net::SocketAddr;

#[derive(serde::Deserialize)]
struct Config {
    ip_source: SecureClientIpSource,
}

async fn handler(MaybeSecureClientIp(ip): MaybeSecureClientIp) -> String {
    format!("{ip:?}")
}

#[tokio::main]
async fn main() {
    let config: Config = envy::from_env().unwrap();

    let app = Router::new()
        .route("/", get(handler))
        // the line you're probably looking for :)
        .layer(config.ip_source.into_extension());

    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap()
}
