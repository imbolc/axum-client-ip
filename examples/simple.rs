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
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap()
}
