// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2025-2026 Dendri contributors

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "dendri", about = "Dendri signaling server (Rust + Redis)")]
#[clap(rename_all = "snake_case")]
pub struct Config {
    /// Server listen port
    #[arg(short, long, default_value_t = 9000, env = "PORT")]
    pub port: u16,

    /// Server bind address
    #[arg(short = 'H', long, default_value = "::")]
    pub host: String,

    /// Connection key (used if --key-file is not provided)
    #[arg(short, long, default_value = "dendri", env = "DENDRI_KEY")]
    pub key: String,

    /// Path to a file containing the connection key.
    /// Overrides --key if both are set. More secure than --key
    /// because it avoids exposing the secret in process listings.
    #[arg(long, env = "DENDRI_KEY_FILE")]
    pub key_file: Option<PathBuf>,

    /// URL path prefix
    #[arg(long, default_value = "/", env = "PEERSERVER_PATH")]
    pub path: String,

    /// Max simultaneous clients
    #[arg(short, long, default_value_t = 10000)]
    pub concurrent_limit: usize,

    /// Heartbeat timeout (milliseconds)
    #[arg(long, default_value_t = 60000)]
    pub alive_timeout: u64,

    /// Idle timeout (milliseconds) — clients with no data/room messages for
    /// this duration are evicted even if they are sending HEARTBEATs.
    /// Defaults to 15 minutes (900000 ms). Set to 0 to disable.
    #[arg(long, default_value_t = 900_000)]
    pub idle_timeout: u64,

    /// Message queue expiration timeout (milliseconds)
    #[arg(short = 't', long, default_value_t = 5000)]
    pub expire_timeout: u64,

    /// Allow discovery of peers via GET /:key/peers
    #[arg(long, env = "DENDRI_ALLOW_DISCOVERY")]
    pub allow_discovery: bool,

    /// Optional token required to call GET /:key/peers (in addition to --key).
    /// When set, callers must pass ?token=<value> to the peers endpoint.
    /// More secure than --allow_discovery alone because the discovery token
    /// can be kept separate from the connection key.
    #[arg(long, env = "DENDRI_DISCOVERY_TOKEN")]
    pub discovery_token: Option<String>,

    /// Message cleanup interval (milliseconds)
    #[arg(long, default_value_t = 1000)]
    pub cleanup_out_msgs: u64,

    /// CORS origins (repeat for multiple)
    #[arg(long)]
    pub cors: Vec<String>,

    /// Path to SSL private key
    #[arg(long)]
    pub sslkey: Option<String>,

    /// Path to SSL certificate
    #[arg(long)]
    pub sslcert: Option<String>,

    /// Enable WebSocket data relay (hybrid mode)
    #[arg(long, env = "DENDRI_ENABLE_RELAY")]
    pub enable_relay: bool,

    /// Maximum message payload size in bytes
    #[arg(long, default_value_t = 65536)]
    pub max_message_size: usize,

    /// Signaling messages per second per client
    #[arg(long, default_value_t = 50)]
    pub rate_limit_signaling: u32,

    /// Data messages per second per client
    #[arg(long, default_value_t = 100)]
    pub rate_limit_data: u32,

    /// HMAC secret for ephemeral TURN credentials
    #[arg(long, env = "TURN_SECRET")]
    pub turn_secret: Option<String>,

    /// TURN server URLs
    #[arg(long)]
    pub turn_servers: Vec<String>,

    /// Maximum number of clients allowed per room (0 = unlimited)
    #[arg(long, default_value_t = 50)]
    pub max_room_size: usize,

    /// Maximum rooms a single client may join (0 = unlimited)
    #[arg(long, default_value_t = 32, env = "DENDRI_MAX_ROOMS_PER_CLIENT")]
    pub max_rooms_per_client: usize,

    /// Maximum distinct rooms server-wide (0 = unlimited)
    #[arg(long, default_value_t = 10000, env = "DENDRI_MAX_TOTAL_ROOMS")]
    pub max_total_rooms: usize,

    /// Max messages per client replay buffer
    #[arg(long, default_value_t = 1000)]
    pub replay_buffer_size: usize,

    /// Replay buffer TTL in milliseconds
    #[arg(long, default_value_t = 300000)]
    pub replay_buffer_ttl: u64,

    /// Grace period (ms) before removing disconnected clients from rooms (0 = immediate)
    #[arg(long, default_value_t = 30000, env = "DENDRI_SESSION_TTL")]
    pub session_ttl: u64,

    /// JWT secret for token validation (optional — if not set, JWT auth is disabled)
    #[arg(long, env = "DENDRI_JWT_SECRET")]
    pub jwt_secret: Option<String>,

    /// Admin API bearer token. Setting this mounts the /admin tenant CRUD routes.
    #[arg(long, env = "DENDRI_ADMIN_TOKEN")]
    pub admin_token: Option<String>,

    /// Require a valid tenant API key on every connection (hosted/SaaS mode).
    /// Off = self-host mode: connections without an api_key use the shared key only.
    #[arg(long, env = "DENDRI_REQUIRE_API_KEY")]
    pub require_api_key: bool,

    /// Alibaba DirectMail RAM access key id (enables dashboard magic-link email).
    #[arg(long, env = "DENDRI_MAIL_AK_ID")]
    pub mail_ak_id: Option<String>,

    /// Alibaba DirectMail RAM access key secret.
    #[arg(long, env = "DENDRI_MAIL_AK_SECRET")]
    pub mail_ak_secret: Option<String>,

    /// DirectMail region (endpoint dm.<region>.aliyuncs.com).
    #[arg(long, env = "DENDRI_MAIL_REGION", default_value = "ap-southeast-1")]
    pub mail_region: String,

    /// From address for transactional email.
    #[arg(long, env = "DENDRI_MAIL_FROM", default_value = "noreply@dendri.dev")]
    pub mail_from: String,

    /// Base URL of the customer dashboard (used in magic-link emails).
    #[arg(
        long,
        env = "DENDRI_DASHBOARD_URL",
        default_value = "https://app.dendri.dev"
    )]
    pub dashboard_url: String,

    /// Webhook URL to receive server event notifications (optional)
    #[arg(long, env = "DENDRI_WEBHOOK_URL")]
    pub webhook_url: Option<String>,

    /// Webhook secret for HMAC-SHA256 signing (optional)
    #[arg(long, env = "DENDRI_WEBHOOK_SECRET")]
    pub webhook_secret: Option<String>,

    /// Redis connection URL
    #[arg(long, env = "REDIS_URL", default_value = "redis://127.0.0.1:6379")]
    pub redis_url: String,

    /// Strip ICE candidates from SDP before forwarding (privacy: prevents IP leaks)
    #[arg(long, env = "DENDRI_STRIP_ICE_CANDIDATES")]
    pub strip_ice_candidates: bool,
}
