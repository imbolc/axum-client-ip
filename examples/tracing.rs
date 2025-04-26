//! An example of integration with Tracing
use std::net::SocketAddr;

use axum::{
    Router,
    extract::{self, FromRequestParts},
    http::{self},
    middleware::{self, Next},
    routing::get,
};
use axum_client_ip::{ClientIp, ClientIpSource};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::{Span, info, info_span, level_filters::LevelFilter};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::TRACE.into())
                .from_env_lossy(),
        )
        .with(fmt::layer())
        .init();

    let app = Router::new()
        .route(
            "/",
            get(async || {
                info!("hi");
                "Hello, World!"
            }),
        )
        .layer(
            ServiceBuilder::new()
                // Hardcode IP source, look into `examples/configurable.rs` for runtime
                // configuration
                .layer(ClientIpSource::ConnectInfo.into_extension())
                // Create a request span with a placeholder for IP
                .layer(
                    TraceLayer::new_for_http().make_span_with(|request: &http::Request<_>| {
                        info_span!(
                            "request",
                            method = %request.method(),
                            uri = %request.uri(),
                            ip = tracing::field::Empty
                        )
                    }),
                )
                // Extract IP and fill the span placeholder
                .layer(middleware::from_fn(
                    async |request: extract::Request, next: Next| {
                        let (mut parts, body) = request.into_parts();
                        if let Ok(ip) = ClientIp::from_request_parts(&mut parts, &()).await {
                            let span = Span::current();
                            span.record("ip", ip.0.to_string());
                        }
                        next.run(extract::Request::from_parts(parts, body)).await
                    },
                )),
        );

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let listener = TcpListener::bind(&addr).await.unwrap();

    println!("Listening on http://localhost:3000/");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap()
}
