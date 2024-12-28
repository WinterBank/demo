// api/src/utils.rs

use redis::AsyncCommands;
use redis::Client as RedisClient;
use crate::routes::{MiningSubmission, TransactionData};
use blake3::Hasher as Blake3Hasher;
use sqlx::PgPool;

// Caching Functions

/// Caches the mapping from account name to public key in Redis.
/// The public key is stored as a hex-encoded string.
pub async fn cache_account_name_to_public_key(
    redis: &RedisClient,
    name: &str,
    public_key: &[u8],
) -> redis::RedisResult<()> {
    let mut con = redis.get_multiplexed_async_connection().await?;
    con.set(format!("account:name:{}", name), hex::encode(public_key)).await
}

/// Retrieves the public key associated with an account name from Redis.
/// Returns `None` if the account name does not exist or decoding fails.
pub async fn get_public_key_from_cache(redis: &RedisClient, name: &str) -> Option<Vec<u8>> {
    let mut con = redis.get_multiplexed_async_connection().await.ok()?;
    let val: Option<String> = con.get(format!("account:name:{}", name)).await.ok()?;
    val.and_then(|hex_str| hex::decode(&hex_str).ok())
}

/// Caches sub-account information (account key and balance) in Redis.
pub async fn cache_sub_account(
    redis: &RedisClient,
    public_key: &[u8],
    sub_name: &str,
    account_key: &[u8],
    balance: i64,
) -> redis::RedisResult<()> {
    let pk_hex = hex::encode(public_key);
    let mut con = redis.get_multiplexed_async_connection().await?;
    let _: () = con.set(format!("account_keys:{}:{}:key", pk_hex, sub_name), hex::encode(account_key)).await?;
    let _: () = con.set(format!("account_keys:{}:{}:balance", pk_hex, sub_name), balance).await?;
    Ok(())
}

/// Retrieves sub-account information (account key and balance) from Redis.
/// Returns `None` if the sub-account does not exist or decoding fails.
pub async fn get_sub_account_from_cache(
    redis: &RedisClient,
    public_key: &[u8],
    sub_name: &str,
) -> Option<(Vec<u8>, i64)> {
    let pk_hex = hex::encode(public_key);
    let mut con = redis.get_multiplexed_async_connection().await.ok()?;
    let key_hex: Option<String> = con.get(format!("account_keys:{}:{}:key", pk_hex, sub_name)).await.ok()?;
    let balance: Option<i64> = con.get(format!("account_keys:{}:{}:balance", pk_hex, sub_name)).await.ok()?;

    match (key_hex, balance) {
        (Some(k), Some(b)) => {
            if let Ok(k_bytes) = hex::decode(&k) {
                Some((k_bytes, b))
            } else {
                None
            }
        },
        _ => None,
    }
}

/// Updates the balance of a sub-account in Redis.
pub async fn update_sub_account_balance(
    redis: &RedisClient,
    public_key: &[u8],
    sub_name: &str,
    balance: i64,
) -> redis::RedisResult<()> {
    let pk_hex = hex::encode(public_key);
    let mut con = redis.get_multiplexed_async_connection().await?;
    con.set(format!("account_keys:{}:{}:balance", pk_hex, sub_name), balance).await
}

/// Caches the latest Merkle Root in Redis as a hex-encoded string.
pub async fn cache_merkle_root(redis: &RedisClient, root: &[u8; 32]) -> redis::RedisResult<()> {
    let mut con = redis.get_multiplexed_async_connection().await?;
    con.set("transaction_root:latest", hex::encode(root)).await
}

/// Enqueues a mining submission into Redis.
/// Serializes the submission and pushes it to the `mining_submission_queue`.
///
/// # Arguments
/// * `redis` - Reference to the Redis client.
/// * `account_key` - The account key of the miner.
/// * `nonce` - The nonce used in the mining submission.
/// * `hash` - The hash of the mining result.
/// * `salt` - The salt used during hashing.
///
/// # Returns
/// * `Ok(())` if the submission is enqueued successfully.
/// * `Err(redis::RedisError)` if an error occurs during the operation.
pub async fn enqueue_mining_submission(
    redis: &RedisClient,
    account_key: Vec<u8>,
    nonce: u64,
    hash: Vec<u8>,
    salt: Vec<u8>,
) -> redis::RedisResult<()> {
    let submission = MiningSubmission {
        account_key: account_key.into(),
        nonce,
        hash: hash.into(),
        salt,
    };

    let serialized_submission = match serde_json::to_vec(&submission) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Serialization error: {}", e);
            return Err(redis::RedisError::from((
                redis::ErrorKind::TypeError,
                "Serialization error",
                e.to_string(),
            )));
        }
    };

    println!("Serialized submission: {:?}", hex::encode(&serialized_submission));

    // Get the Redis connection
    let mut con = redis.get_multiplexed_async_connection().await?;

    match con.rpush::<_, _, ()>("mining_submission_queue", serialized_submission).await {
        Ok(_) => {
            println!("Successfully enqueued mining submission.");
            Ok(())
        },
        Err(e) => {
            eprintln!("Failed to enqueue mining submission: {}", e);
            Err(e)
        }
    }
}

pub async fn dequeue_mining_submission(redis_client: &RedisClient) -> Option<MiningSubmission> {
    println!("Starting dequeue mining submission...");
    let mut con = redis_client.get_multiplexed_async_connection().await.ok()?;

    // Call lpop with None as the count, indicating we only want one element.
    let data: Option<Vec<u8>> = con.lpop("mining_submission_queue", None).await.ok()?;

    if let Some(bytes) = &data {
        println!("Dequeued mining submission: {:?}", hex::encode(bytes));
    } else {
        eprintln!("Failed to dequeue mining submission: Data is None");
    }

    data.and_then(|bytes| serde_json::from_slice(&bytes).ok())
}

/// Enqueues a serialized transaction into Redis.
/// Validates that the data is non-empty and correctly formatted.
pub async fn enqueue_transaction(redis: &RedisClient, data: &[u8]) -> redis::RedisResult<()> {
    if data.is_empty() {
        eprintln!("Attempted to enqueue empty transaction data.");
        return Err(redis::RedisError::from((redis::ErrorKind::TypeError, "Empty transaction data")));
    }

    if serde_json::from_slice::<TransactionData>(data).is_err() {
        eprintln!("Attempted to enqueue malformed transaction data.");
        return Err(redis::RedisError::from((redis::ErrorKind::TypeError, "Malformed transaction data")));
    }

    let mut con = redis.get_multiplexed_async_connection().await?;

    match con.rpush::<_, _, ()>("transaction_queue", data).await {
        Ok(_) => {
            println!("Successfully enqueued transaction.");
            Ok(())
        },
        Err(e) => {
            eprintln!("Failed to enqueue transaction: {}", e);
            Err(e)
        }
    }
}

/// Dequeues a transaction from Redis.
/// Returns `None` if the queue is empty or an error occurs.
pub async fn dequeue_transaction(redis: &RedisClient) -> Option<Vec<u8>> {
    let mut con = redis.get_multiplexed_async_connection().await.ok()?;
    let data: Option<Vec<u8>> = con.lpop("transaction_queue", None).await.ok()?;
    if data.is_none() {
        println!("No transaction found in queue.");
    } else {
        println!("Dequeued transaction: {:?}", data);
    }
    data
}

/// Retrieves the public key associated with an account key from Redis.
/// Returns `None` if the account key does not exist or decoding fails.
pub async fn get_public_key_from_account_key(redis: &RedisClient, account_key: &[u8]) -> Option<Vec<u8>> {
    let pk_hex = hex::encode(account_key);
    let mut con = redis.get_multiplexed_async_connection().await.ok()?;
    con.get(format!("public_key:account_key:{}", pk_hex)).await.ok()
}

/// Retrieves the balance of a sub-account from Redis.
/// Returns `None` if the balance does not exist or an error occurs.
pub async fn get_balance(redis: &RedisClient, public_key: &[u8], sub_name: &str) -> Option<i64> {
    let pk_hex = hex::encode(public_key);
    let mut con = redis.get_multiplexed_async_connection().await.ok()?;
    con.get(format!("account_keys:{}:{}:balance", pk_hex, sub_name)).await.ok()
}

/// Resolves an account identifier to an account key using cached data.
/// If the account key is not in the cache, it returns `None`.
pub async fn resolve_account_key_with_cache(
    redis: &RedisClient,
    account_key: &[u8]
) -> Option<[u8; 16]> {
    if let Some(public_key) = get_public_key_from_account_key(redis, account_key).await {
        let mut key = [0u8; 16];
        key.copy_from_slice(&public_key[..16]);
        Some(key)
    } else {
        None
    }
}

// Serialization and Deserialization

/// Serializes a transaction into a byte vector.
/// Example uses `serde_json` for serialization.
pub fn serialize_transaction(
    sender_key: &[u8],
    receiver_key: &[u8],
    amount: i64,
) -> Vec<u8> {
    // Implement actual serialization (e.g., using serde_json or bincode)
    // Example using serde_json:
    let tx = TransactionData {
        sender_key: sender_key.to_vec(),
        receiver_key: receiver_key.to_vec(),
        amount,
        signature: vec![], // Fill with actual signature
        nonce: [0u8; 8],   // Fill with actual nonce
    };
    serde_json::to_vec(&tx).unwrap_or_else(|_| vec![])
}

/// Deserializes a byte slice into a `TransactionData` struct.
/// Returns an error if deserialization fails.
pub fn deserialize_transaction(data: &[u8]) -> Result<TransactionData, ()> {
    serde_json::from_slice(data).map_err(|_| ())
}

// Remaining Helper Functions

/// Resolves an account identifier (either a composite `sub_name.main_name` or a direct name/key)
/// to an account key by querying the database.
///
/// # Arguments
///
/// * `pool` - Reference to the PostgreSQL connection pool.
/// * `identifier` - The account identifier to resolve.
///
/// # Returns
///
/// * `Ok([u8; 16])` if the account key is successfully resolved.
/// * `Err(String)` if the account cannot be found or a database error occurs.
pub async fn resolve_account_key(pool: &PgPool, identifier: &str) -> Result<[u8; 16], String> {
    // Check if it’s sub_name.main_name format
    let parts: Vec<&str> = identifier.split('.').collect();
    if parts.len() == 2 {
        let sub_name = parts[0];
        let main_name = parts[1];

        let public_key_opt = sqlx::query!(
            "SELECT public_key FROM accounts WHERE name = $1",
            main_name
        )
        .fetch_optional(pool)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

        let public_key = match public_key_opt {
            Some(r) => r.public_key,
            None => return Err(format!("Main account '{}' not found", main_name)),
        };

        let ak_opt = sqlx::query!(
            "SELECT account_key FROM account_keys WHERE public_key = $1 AND sub_name = $2",
            &public_key,
            sub_name
        )
        .fetch_optional(pool)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

        if let Some(r) = ak_opt {
            let mut key = [0u8; 16];
            key.copy_from_slice(&r.account_key);
            Ok(key)
        } else {
            Err(format!("Sub-account '{}.{}' not found", sub_name, main_name))
        }
    } else {
        // No dot means either main_name or a 16-byte hex key
        if let Ok(decoded) = hex::decode(identifier) {
            if decoded.len() == 16 {
                // Direct account_key lookup
                let ak_opt = sqlx::query!(
                    "SELECT account_key FROM account_keys WHERE account_key = $1",
                    &decoded
                )
                .fetch_optional(pool)
                .await
                .map_err(|e| format!("Database error: {}", e))?;

                if ak_opt.is_some() {
                    let mut key = [0u8; 16];
                    key.copy_from_slice(&decoded);
                    return Ok(key);
                } else {
                    return Err(format!("account_key '{}' not found", identifier));
                }
            }
        }

        // Treat as main_name
        let public_key_opt = sqlx::query!(
            "SELECT public_key FROM accounts WHERE name = $1",
            identifier
        )
        .fetch_optional(pool)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

        let public_key = match public_key_opt {
            Some(r) => r.public_key,
            None => return Err(format!("Main account '{}' not found", identifier)),
        };

        // Get main sub-account_key
        let ak_opt = sqlx::query!(
            "SELECT account_key FROM account_keys WHERE public_key = $1 AND sub_name = 'main'",
            &public_key
        )
        .fetch_optional(pool)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

        if let Some(r) = ak_opt {
            let mut key = [0u8; 16];
            key.copy_from_slice(&r.account_key);
            Ok(key)
        } else {
            Err(format!("Main sub-account not found for '{}'", identifier))
        }
    }
}

/// Computes a unique transaction ID by hashing the transaction fields using BLAKE3.
///
/// # Arguments
///
/// * `sender_key` - Sender's public key.
/// * `receiver_key` - Receiver's public key.
/// * `amount` - Transaction amount.
/// * `signature` - Transaction signature.
/// * `nonce` - Transaction nonce.
///
/// # Returns
///
/// * `[u8; 32]` array representing the transaction ID.
pub fn compute_transaction_id(
    sender_key: &[u8],
    receiver_key: &[u8],
    amount: i64,
    signature: &[u8],
    nonce: &[u8; 8],
) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new();
    hasher.update(sender_key);
    hasher.update(receiver_key);
    hasher.update(&amount.to_be_bytes());
    hasher.update(signature);
    hasher.update(nonce);
    let hash = hasher.finalize();
    *hash.as_bytes()
}

/// Resolves an account name to an account key by querying the database.
/// This is a duplicate function from `resolve_account_key` but can be removed
/// if not needed.
///
/// # Arguments
///
/// * `pool` - Reference to the PostgreSQL connection pool.
/// * `name` - The account name to resolve.
///
/// # Returns
///
/// * `Ok([u8; 16])` if the account key is found.
/// * `Err(String)` if the account is not found or a database error occurs.
pub async fn get_account_key(pool: &PgPool, name: &str) -> Result<[u8; 16], String> {
    println!("Fetching account key for name: {}", name);

    let mut conn = pool.acquire().await.map_err(|_| "Failed to acquire a database connection")?;

    // Step 1: Get public_key from accounts by name
    let public_key_rec = sqlx::query!(
        "SELECT public_key FROM accounts WHERE name = $1",
        name
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| format!("Database error: {}", e))?;

    let public_key = match public_key_rec {
        Some(rec) => rec.public_key,
        None => return Err(format!("Account with name '{}' not found", name)),
    };

    // Step 2: Get the main account_key from account_keys by public_key and sub_name='main'
    let account_key_rec = sqlx::query!(
        "SELECT account_key FROM account_keys WHERE public_key = $1 AND sub_name = 'main'",
        &public_key
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| format!("Database error: {}", e))?;

    match account_key_rec {
        Some(record) => {
            let key = record.account_key;
            if key.len() == 16 {
                let mut array = [0u8; 16];
                array.copy_from_slice(&key); // Convert Vec<u8> to [u8; 16]
                Ok(array)
            } else {
                Err("Invalid account_key length in database.".to_string())
            }
        }
        None => Err(format!("No main sub-account found for '{}'", name)),
    }
}

/// Tests the Redis connection by attempting to establish an asynchronous connection.
/// Returns `true` if successful, `false` otherwise.
pub async fn test_redis_connection(redis_client: &RedisClient) -> bool {
    match redis_client.get_multiplexed_async_connection().await {
        Ok(_) => true,
        Err(err) => {
            eprintln!("Failed to connect to Redis: {}", err);
            false
        }
    }
}

/// Pads Leaves in merkle tree to achieve power of 2
pub fn pad_leaves_to_power_of_two(mut leaves: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    if leaves.is_empty() {
        eprintln!("No leaves available to pad for Merkle Tree."); // Debugging log
        leaves.push([0u8; 32]); // Ensure at least one leaf
        return leaves;
    }
    let len = leaves.len();
    if len.is_power_of_two() {
        return leaves;
    }
    let last_leaf = *leaves.last().unwrap();
    let next_power_of_two = len.next_power_of_two();
    while leaves.len() < next_power_of_two {
        leaves.push(last_leaf);
    }
    leaves
}

/// Counts the number of leading zero bits in a 32-byte hash.
/// Stops counting after the first non-zero byte.
pub fn count_leading_zero_bits(hash: &[u8; 32]) -> u64 {
    let mut count = 0;
    for byte in hash.iter() {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros() as u64;
            break;
        }
    }
    count
}
