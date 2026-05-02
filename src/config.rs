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

    /// Connection key
    #[arg(short, long, default_value = "dendri")]
    pub key: String,

    /// URL path prefix
    #[arg(long, default_value = "/", env = "PEERSERVER_PATH")]
    pub path: String,

    /// Max simultaneous clients
    #[arg(short, long, default_value_t = 5000)]
    pub concurrent_limit: usize,

    /// Heartbeat timeout (milliseconds)
    #[arg(long, default_value_t = 60000)]
    pub alive_timeout: u64,

    /// Message queue expiration timeout (milliseconds)
    #[arg(short = 't', long, default_value_t = 5000)]
    pub expire_timeout: u64,

    /// Allow discovery of peers via GET /:key/peers
    #[arg(long, env = "DENDRI_ALLOW_DISCOVERY")]
    pub allow_discovery: bool,

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
    #[arg(long, default_value_t = 10)]
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

    /// Webhook URL to receive server event notifications (optional)
    #[arg(long, env = "DENDRI_WEBHOOK_URL")]
    pub webhook_url: Option<String>,

    /// Webhook secret for HMAC-SHA256 signing (optional)
    #[arg(long, env = "DENDRI_WEBHOOK_SECRET")]
    pub webhook_secret: Option<String>,

    /// Redis connection URL
    #[arg(long, env = "REDIS_URL", default_value = "redis://127.0.0.1:6379")]
    pub redis_url: String,
}
