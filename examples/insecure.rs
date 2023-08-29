use axum::{routing::get, Router};
use axum_client_ip::InsecureClientIp;
use std::net::SocketAddr;

async fn handler(InsecureClientIp(ip): InsecureClientIp) -> String {
    ip.to_string()
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/", get(handler));

    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(
            // Don't forget to add `ConnectInfo`
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap()
}
