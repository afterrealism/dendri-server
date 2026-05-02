use redis::aio::ConnectionManager;
use redis::AsyncCommands;

/// Register a new client in Redis.
/// Stores token and last_ping in a hash, adds ID to the clients set,
/// and sets a safety TTL of 2 * alive_timeout.
pub async fn register_client(
    conn: &ConnectionManager,
    id: &str,
    token: &str,
    alive_timeout_ms: u64,
) -> redis::RedisResult<()> {
    let mut conn = conn.clone();
    let client_key = format!("peer:client:{id}");
    let now = now_ms();

    let _: () = redis::pipe()
        .hset(&client_key, "token", token)
        .hset(&client_key, "last_ping", now.to_string())
        .sadd("peer:clients", id)
        .expire(&client_key, ttl_seconds(alive_timeout_ms))
        .query_async(&mut conn)
        .await?;

    Ok(())
}

/// Remove a client from Redis: delete its hash and remove from the clients set.
pub async fn remove_client(conn: &ConnectionManager, id: &str) -> redis::RedisResult<()> {
    let mut conn = conn.clone();
    let client_key = format!("peer:client:{id}");

    let _: () = redis::pipe()
        .del(&client_key)
        .srem("peer:clients", id)
        .query_async(&mut conn)
        .await?;

    Ok(())
}

/// Check if a client exists in Redis.
pub async fn client_exists(conn: &ConnectionManager, id: &str) -> redis::RedisResult<bool> {
    let mut conn = conn.clone();
    conn.sismember("peer:clients", id).await
}

/// Get a client's token from Redis.
pub async fn get_client_token(
    conn: &ConnectionManager,
    id: &str,
) -> redis::RedisResult<Option<String>> {
    let mut conn = conn.clone();
    let client_key = format!("peer:client:{id}");
    conn.hget(&client_key, "token").await
}

/// Get a client's last_ping timestamp from Redis.
pub async fn get_client_last_ping(
    conn: &ConnectionManager,
    id: &str,
) -> redis::RedisResult<Option<i64>> {
    let mut conn = conn.clone();
    let client_key = format!("peer:client:{id}");
    let val: Option<String> = conn.hget(&client_key, "last_ping").await?;
    Ok(val.and_then(|v| v.parse::<i64>().ok()))
}

/// Update a client's last_ping and refresh the TTL.
pub async fn set_last_ping(
    conn: &ConnectionManager,
    id: &str,
    alive_timeout_ms: u64,
) -> redis::RedisResult<()> {
    let mut conn = conn.clone();
    let client_key = format!("peer:client:{id}");
    let now = now_ms();

    let _: () = redis::pipe()
        .hset(&client_key, "last_ping", now.to_string())
        .expire(&client_key, ttl_seconds(alive_timeout_ms))
        .query_async(&mut conn)
        .await?;

    Ok(())
}

/// Return the number of connected clients.
pub async fn client_count(conn: &ConnectionManager) -> redis::RedisResult<usize> {
    let mut conn = conn.clone();
    conn.scard("peer:clients").await
}

/// Return all connected client IDs.
pub async fn get_all_client_ids(conn: &ConnectionManager) -> redis::RedisResult<Vec<String>> {
    let mut conn = conn.clone();
    conn.smembers("peer:clients").await
}

/// Generate a unique client ID (UUID v4) that doesn't collide with existing clients.
pub async fn generate_client_id(conn: &ConnectionManager) -> redis::RedisResult<String> {
    loop {
        let id = uuid::Uuid::new_v4().to_string();
        if !client_exists(conn, &id).await? {
            return Ok(id);
        }
    }
}

/// Add a message to a client's queue in Redis.
pub async fn add_message_to_queue(
    conn: &ConnectionManager,
    id: &str,
    message_json: &str,
) -> redis::RedisResult<()> {
    let mut conn = conn.clone();
    let queue_key = format!("peer:queue:{id}");
    let meta_key = format!("peer:queue_meta:{id}");
    let now = now_ms();

    let _: () = redis::pipe()
        .rpush(&queue_key, message_json)
        .set(&meta_key, now.to_string())
        .sadd("peer:queues", id)
        .query_async(&mut conn)
        .await?;

    Ok(())
}

/// Read all messages from a client's queue.
pub async fn read_all_messages(
    conn: &ConnectionManager,
    id: &str,
) -> redis::RedisResult<Vec<String>> {
    let mut conn = conn.clone();
    let queue_key = format!("peer:queue:{id}");
    let meta_key = format!("peer:queue_meta:{id}");
    let now = now_ms();

    // Update last-read-at timestamp
    let _: () = conn.set(&meta_key, now.to_string()).await?;

    conn.lrange(&queue_key, 0, -1).await
}

/// Clear a client's message queue from Redis.
pub async fn clear_message_queue(conn: &ConnectionManager, id: &str) -> redis::RedisResult<()> {
    let mut conn = conn.clone();
    let queue_key = format!("peer:queue:{id}");
    let meta_key = format!("peer:queue_meta:{id}");

    let _: () = redis::pipe()
        .del(&queue_key)
        .del(&meta_key)
        .srem("peer:queues", id)
        .query_async(&mut conn)
        .await?;

    Ok(())
}

/// Get all client IDs that have pending message queues.
pub async fn get_client_ids_with_queue(
    conn: &ConnectionManager,
) -> redis::RedisResult<Vec<String>> {
    let mut conn = conn.clone();
    conn.smembers("peer:queues").await
}

/// Get the last-read-at timestamp for a client's queue.
pub async fn get_queue_last_read_at(
    conn: &ConnectionManager,
    id: &str,
) -> redis::RedisResult<Option<i64>> {
    let mut conn = conn.clone();
    let meta_key = format!("peer:queue_meta:{id}");
    let val: Option<String> = conn.get(&meta_key).await?;
    Ok(val.and_then(|v| v.parse::<i64>().ok()))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn ttl_seconds(alive_timeout_ms: u64) -> i64 {
    ((alive_timeout_ms * 2) / 1000).max(1) as i64
}
