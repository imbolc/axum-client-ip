use axum::{routing::get, Router};
use axum_client_ip::InsecureClientIp;
use std::net::SocketAddr;

async fn handler(InsecureClientIp(ip): InsecureClientIp) -> String {
    ip.to_string()
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/", get(handler));

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
