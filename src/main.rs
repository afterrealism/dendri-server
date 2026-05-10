// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2025-2026 Dendri contributors

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod config;
mod enums;
mod handlers;
mod models;
mod pii;
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
use metrics_exporter_prometheus::PrometheusBuilder;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::Span;

use config::Config;
use state::AppState;

#[tokio::main]
async fn main() {
    // Panic hook emits structured tracing so panics in background tasks
    // are captured with context instead of disappearing silently.
    std::panic::set_hook(Box::new(|info| {
        let payload = info.payload();
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_default();
        let msg = payload
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| payload.downcast_ref::<String>().map(|s| s.as_str()))
            .unwrap_or("unknown");
        tracing::error!(panic.location = %location, panic.msg = %msg, "Panic");
        eprintln!("FATAL: {} at {}", msg, location);
    }));

    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "dendri=info".into()),
        )
        .init();

    // Initialize Prometheus metrics recorder.
    let prometheus_handle = PrometheusBuilder::new()
        .install_recorder()
        .expect("Failed to install Prometheus recorder");

    let config = {
        let mut c = Config::parse();

        // If --key-file is provided, read the key from the file,
        // overriding any value from --key or DENDRI_KEY env var.
        if let Some(ref path) = c.key_file {
            match std::fs::read_to_string(path) {
                Ok(mut key) => {
                    key.truncate(key.trim_end().len());
                    if key.is_empty() {
                        eprintln!("Key file {path:?} is empty");
                        std::process::exit(1);
                    }
                    c.key = key;
                }
                Err(e) => {
                    eprintln!("Failed to read key file {path:?}: {e}");
                    std::process::exit(1);
                }
            }
        }

        c
    };

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
    let mut app = Router::new()
        .route("/health", get(handlers::api::health))
        .route(
            "/metrics",
            get(move || {
                let handle = prometheus_handle.clone();
                async move { handle.render() }
            }),
        )
        .route("/turn", get(handlers::api::turn_credentials_root))
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
        .fallback(|| async {
            (
                axum::http::StatusCode::NOT_FOUND,
                axum::Json(serde_json::json!({"error": "Not Found"})),
            )
        })
        .layer(cors)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &axum::http::Request<_>| {
                    tracing::info_span!(
                        "request",
                        method = %request.method(),
                        uri = %request.uri(),
                        version = ?request.version(),
                    )
                })
                .on_request(|request: &axum::http::Request<_>, _span: &Span| {
                    tracing::info!(
                        method = %request.method(),
                        uri = %request.uri(),
                        "-> incoming request"
                    );
                })
                .on_response(
                    |response: &axum::http::Response<_>, latency: std::time::Duration, _span: &Span| {
                        tracing::info!(
                            status = response.status().as_u16(),
                            latency_ms = latency.as_millis(),
                            "<- response"
                        );
                    },
                ),
        )
        .with_state(state.clone());

    // HSTS: only active when TLS is configured.
    if sslkey.is_some() {
        use axum::http::header::STRICT_TRANSPORT_SECURITY;
        use axum::http::HeaderValue;
        let hsts = HeaderValue::from_static("max-age=31536000; includeSubDomains");
        app = app.layer(axum::middleware::from_fn(
            move |_req, next: axum::middleware::Next| {
                let hsts = hsts.clone();
                async move {
                    let mut resp = next.run(_req).await;
                    resp.headers_mut().insert(STRICT_TRANSPORT_SECURITY, hsts);
                    resp
                }
            },
        ));
    }

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

    // Graceful WS drain: send CLOSE to all live clients, wait up to 30 s.
    let _ = state.drain_ws(4001, "shutting-down").await;

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

    // SIGHUP handler: reload TLS certificates from disk without restarting.
    #[cfg(unix)]
    {
        let reload_config = tls_config.clone();
        let reload_key = key_path.to_string();
        let reload_cert = cert_path.to_string();
        tokio::spawn(async move {
            let Ok(mut sighup) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            else {
                return;
            };
            loop {
                sighup.recv().await;
                tracing::info!("SIGHUP received, reloading TLS certificates");
                if let Err(e) = reload_config
                    .reload_from_pem_file(&reload_cert, &reload_key)
                    .await
                {
                    tracing::error!(error = %e, "Failed to reload TLS certificates");
                }
            }
        });
    }

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
    use axum::http::HeaderValue;
    use axum::http::Method;

    let explicit: Vec<HeaderValue> = origins.iter().filter_map(|o| o.parse().ok()).collect();

    let cors = if explicit.is_empty() {
        // No origins configured: allow all *.dendri.dev subdomains by default
        // so that example apps at chat.dendri.dev, cursors.dendri.dev, etc.
        // can reach the signaling server without explicit per-origin config.
        CorsLayer::new().allow_origin(AllowOrigin::predicate(|origin: &HeaderValue, _| {
            let s = origin.as_bytes();
            s.ends_with(b".dendri.dev")
                || s == b"https://dendri.dev"
                || s == b"http://localhost:5173"
        }))
    } else {
        CorsLayer::new().allow_origin(AllowOrigin::list(explicit))
    };

    cors.allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            axum::http::header::ACCEPT,
        ])
        .allow_credentials(true)
        .max_age(std::time::Duration::from_secs(3600))
}
