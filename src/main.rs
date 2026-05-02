#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod config;
mod enums;
mod handlers;
mod models;
mod rate_limiter;
mod redis_realm;
mod replay_buffer;
mod services;
mod state;
mod validation;
mod webhook;

use std::net::SocketAddr;

use axum::routing::{get, post};
use axum::Router;
use clap::Parser;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tower_http::cors::{AllowOrigin, CorsLayer};

use config::Config;
use state::AppState;

#[tokio::main]
async fn main() {
    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "dendri=info".into()),
        )
        .init();

    let config = Config::parse();

    let host = config.host.clone();
    let port = config.port;
    let user_path = config.path.clone();
    let sslkey = config.sslkey.clone();
    let sslcert = config.sslcert.clone();

    // Build app state.
    let state = match AppState::new(config).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to connect to Redis: {e}");
            std::process::exit(1);
        }
    };

    // Build the path prefix. Ensure it starts with / and doesn't end with /.
    let base = normalize_path(&user_path);

    // Build CORS layer.
    let cors = build_cors(&state.config.cors);

    // Build router.
    // axum 0.7 uses `:param` syntax for path parameters.
    let app = Router::new()
        .route("/health", get(handlers::api::health))
        .route(&format!("{base}/"), get(handlers::api::root))
        .route(&format!("{base}/:key/id"), get(handlers::api::get_id))
        .route(&format!("{base}/:key/peers"), get(handlers::api::get_peers))
        .route(
            &format!("{base}/:key/turn-credentials"),
            get(handlers::api::turn_credentials),
        )
        .route(&format!("{base}/dendri"), get(handlers::ws::ws_upgrade))
        .route(
            &format!("{base}/http/sse"),
            get(handlers::http::sse_handler),
        )
        .route(
            &format!("{base}/http/send"),
            post(handlers::http::send_handler),
        )
        .route(
            &format!("{base}/http/poll"),
            get(handlers::http::poll_handler),
        )
        .layer(cors)
        .with_state(state.clone());

    // Shutdown channel for background services.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Spawn background services.
    let check_broken_handle = tokio::spawn(services::check_broken::run(
        state.clone(),
        shutdown_rx.clone(),
    ));
    let messages_expire_handle = tokio::spawn(services::messages_expire::run(
        state.clone(),
        shutdown_rx.clone(),
    ));
    let replay_evict_handle = tokio::spawn(services::replay_evict::run(
        state.clone(),
        shutdown_rx.clone(),
    ));
    let sync_redis_handle = tokio::spawn(services::sync_redis::run(state.clone(), shutdown_rx));

    // Handle TLS if certificates are provided.
    if let (Some(key_path), Some(cert_path)) = (sslkey, sslcert) {
        run_tls(app, &host, port, &key_path, &cert_path, &user_path).await;
    } else {
        run_plain(app, &host, port, &user_path).await;
    }

    // Signal shutdown to background tasks.
    let _ = shutdown_tx.send(true);
    let _ = check_broken_handle.await;
    let _ = messages_expire_handle.await;
    let _ = replay_evict_handle.await;
    let _ = sync_redis_handle.await;
}

async fn run_plain(app: Router, host: &str, port: u16, user_path: &str) {
    let addr: SocketAddr = format!("{host}:{port}").parse().unwrap_or_else(|_| {
        // Fallback: try binding to 0.0.0.0 if :: parsing fails
        format!("0.0.0.0:{port}").parse().expect("Invalid address")
    });

    let listener = TcpListener::bind(addr).await.unwrap_or_else(|e| {
        eprintln!("Failed to bind to {addr}: {e}");
        std::process::exit(1);
    });

    let local_addr = listener.local_addr().unwrap();
    tracing::info!(
        "Started Dendri on {}, port: {}, path: {}",
        local_addr.ip(),
        local_addr.port(),
        if user_path.is_empty() { "/" } else { user_path },
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

async fn run_tls(
    app: Router,
    host: &str,
    port: u16,
    key_path: &str,
    cert_path: &str,
    user_path: &str,
) {
    use axum_server::tls_rustls::RustlsConfig;

    let tls_config = RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .unwrap_or_else(|e| {
            eprintln!("Failed to load TLS certificates: {e}");
            std::process::exit(1);
        });

    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .unwrap_or_else(|_| format!("0.0.0.0:{port}").parse().expect("Invalid address"));

    tracing::info!(
        "Started Dendri (TLS) on {}, port: {}, path: {}",
        addr.ip(),
        port,
        if user_path.is_empty() { "/" } else { user_path },
    );

    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        tokio::select! {
            _ = ctrl_c => {},
            _ = sigterm.recv() => {},
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
    }

    tracing::info!("Shutdown signal received");
}

fn normalize_path(path: &str) -> String {
    let p = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    // Remove trailing slash (but keep the root "/" case working).
    if p.len() > 1 && p.ends_with('/') {
        p[..p.len() - 1].to_string()
    } else if p == "/" {
        String::new()
    } else {
        p
    }
}

fn build_cors(origins: &[String]) -> CorsLayer {
    if origins.is_empty() {
        // Default: mirror origin (allow all).
        CorsLayer::permissive()
    } else {
        let allowed: Vec<_> = origins.iter().filter_map(|o| o.parse().ok()).collect();
        CorsLayer::new().allow_origin(AllowOrigin::list(allowed))
    }
}
