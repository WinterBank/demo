// api/src/batcher.rs

use std::convert::TryInto;
use std::sync::Arc;

use ed25519_dalek::{Signature, Verifier, VerifyingKey}; // single-sig verify
use miner::cpu_miner::CpuMiner;
use redis::Client as RedisClient;
use serde_json::json;
use sqlx::PgPool;
use tokio::sync::broadcast::Sender;

use crate::mining_params::{mining_params, DIFFICULTY};
use crate::routes::{MiningSubmission, TransactionData};
use crate::utils::*;

// The interval at which we compute and store the global state root (in milliseconds)
const STATE_ROOT_INTERVAL: u64 = 60_000; // 1 minute
const FINALITY_TIME_MS: u64 = 10_000;    // 10 seconds

/// Spawns a worker that periodically finalizes transactions in a "batch".
/// Takes `ws_broadcast` to push real-time balance or supply updates.
pub async fn start_transaction_batching_worker(
    pool: PgPool,
    redis_client: Arc<RedisClient>,
    ws_broadcast: Option<Arc<Sender<serde_json::Value>>>,
) {
    loop {
        // Wait for the finality time before attempting a batch.
        tokio::time::sleep(tokio::time::Duration::from_millis(FINALITY_TIME_MS)).await;

        let mut batch = Vec::new();

        // Dequeue all available transactions until no more are found.
        while let Some(tx) = dequeue_transaction(redis_client.as_ref()).await {
            if !tx.is_empty() {
                batch.push(tx);
            }
        }

        if !batch.is_empty() {
            println!("Finalizing transaction batch with {} entries...", batch.len());
            match process_transaction_batch(&pool, batch, ws_broadcast.clone()).await {
                Ok(_) => (),
                Err(e) => eprintln!("Error finalizing transaction batch: {}", e),
            }
        } else {
            println!(
                "No valid transaction data in batch. Sleeping for {} seconds...",
                FINALITY_TIME_MS / 1000
            );
        }
    }
}

/// Spawns a worker that periodically finalizes mining submissions in a "batch".
/// Also takes `ws_broadcast` to push real-time supply updates.
pub async fn start_mining_submission_batching_worker(
    pool: PgPool,
    redis_client: Arc<RedisClient>,
    ws_broadcast: Option<Arc<Sender<serde_json::Value>>>,
) {
    loop {
        // Wait for the finality time before attempting a batch.
        tokio::time::sleep(tokio::time::Duration::from_millis(FINALITY_TIME_MS)).await;

        let mut batch = Vec::new();

        // Dequeue all available mining submissions until no more are found.
        while let Some(submission) = dequeue_mining_submission(redis_client.as_ref()).await {
            if let Ok(serialized) = serde_json::to_vec(&submission) {
                if !serialized.is_empty() {
                    batch.push(serialized);
                }
            }
        }

        if !batch.is_empty() {
            println!("Finalizing mining submission batch with {} entries...", batch.len());
            match process_mining_submission_batch(&pool, batch, ws_broadcast.clone()).await {
                Ok(_) => (),
                Err(e) => eprintln!("Error finalizing mining submission batch: {}", e),
            }
        } else {
            println!(
                "No valid mining submission data in batch. Sleeping for {} seconds...",
                FINALITY_TIME_MS / 1000
            );
        }
    }
}

/// Periodically updates the global state root in the DB.
pub async fn start_state_root_updater(pool: PgPool) {
    loop {
        tokio::time::sleep(tokio::time::Duration::from_millis(STATE_ROOT_INTERVAL)).await;
        if let Err(e) = compute_and_store_global_root(&pool).await {
            eprintln!("Error computing/storing global state root: {}", e);
        }
    }
}

/// Processes a batch of serialized transactions from Redis.
/// If `ws_broadcast` is Some, we fetch and broadcast the *new* balances for sender & receiver.
async fn process_transaction_batch(
    pool: &PgPool,
    batch: Vec<Vec<u8>>,
    ws_broadcast: Option<Arc<Sender<serde_json::Value>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut transactions = Vec::new();

    for raw in &batch {
        if raw.is_empty() {
            continue;
        }

        if let Ok(tx) = deserialize_transaction(raw) {
            if validate_transaction(pool, &tx).await {
                eprintln!("Valid transaction: {:?}", tx);
                transactions.push(tx);
            } else {
                eprintln!("Invalid transaction: {:?}", tx);
            }
        } else {
            eprintln!("Failed to deserialize transaction entry: {:?}", raw);
        }
    }

    if transactions.is_empty() {
        eprintln!("No valid transactions to process in the batch.");
        return Ok(());
    }

    let mut dbtx = pool.begin().await?;

    for tx in &transactions {
        let tx_id = compute_transaction_id(
            &tx.sender_key,
            &tx.receiver_key,
            tx.amount,
            &tx.signature,
            &tx.nonce,
        );

        // Insert the transaction
        sqlx::query!(
            "INSERT INTO transactions (id, sender_key, receiver_key, amount, signature, created_at)
             VALUES ($1, $2, $3, $4, $5, NOW())",
            &tx_id[..],
            &tx.sender_key,
            &tx.receiver_key,
            tx.amount,
            &tx.signature
        )
        .execute(&mut *dbtx)
        .await?;

        // Update balances
        sqlx::query!(
            "UPDATE account_keys SET balance = balance - $1 WHERE account_key = $2",
            tx.amount,
            &tx.sender_key
        )
        .execute(&mut *dbtx)
        .await?;

        sqlx::query!(
            "UPDATE account_keys SET balance = balance + $1 WHERE account_key = $2",
            tx.amount,
            &tx.receiver_key
        )
        .execute(&mut *dbtx)
        .await?;

        // If websockets exist, fetch new balances for both sender & receiver, then broadcast
        if let Some(bc) = &ws_broadcast {
            // 1) fetch sender balance
            let sender_balance = sqlx::query_scalar!(
                "SELECT balance FROM account_keys WHERE account_key = $1",
                &tx.sender_key
            )
            .fetch_one(&mut *dbtx)
            .await?;

            // 2) fetch receiver balance
            let receiver_balance = sqlx::query_scalar!(
                "SELECT balance FROM account_keys WHERE account_key = $1",
                &tx.receiver_key
            )
            .fetch_one(&mut *dbtx)
            .await?;

            // broadcast for sender
            let _ = bc.send(json!({
                "type": "balance_update",
                "account_key": hex::encode(&tx.sender_key),
                "new_balance": sender_balance,
            }));
            // broadcast for receiver
            let _ = bc.send(json!({
                "type": "balance_update",
                "account_key": hex::encode(&tx.receiver_key),
                "new_balance": receiver_balance,
            }));
        }
    }

    dbtx.commit().await?;
    Ok(())
}

/// Processes a batch of mining submissions.  
/// If a miner is rewarded, we fetch + broadcast new supply & new balance for that miner.
async fn process_mining_submission_batch(
    pool: &PgPool,
    batch: Vec<Vec<u8>>,
    ws_broadcast: Option<Arc<Sender<serde_json::Value>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut mining_rewards = Vec::new();

    let mut dbtx = pool.begin().await?;

    for raw in &batch {
        if raw.is_empty() {
            continue;
        }

        if let Ok(submission) = serde_json::from_slice::<MiningSubmission>(raw) {
            eprintln!("Received mining submission: {:?}", submission);
            mining_rewards.push(submission);
        } else {
            eprintln!("Failed to deserialize mining submission entry: {:?}", raw);
        }
    }

    if mining_rewards.is_empty() {
        eprintln!("No valid mining submissions to process in the batch.");
        dbtx.commit().await?;
        return Ok(());
    }

    for reward in &mining_rewards {
        println!("Processing mining reward: {:?}", reward);

        let account_key = reward.account_key.clone();
        let nonce = reward.nonce;
        let salt = reward.salt.clone();

        let miner_public_key = sqlx::query!(
            "SELECT public_key FROM account_keys WHERE account_key = $1",
            &account_key
        )
        .fetch_optional(&mut *dbtx)
        .await?
        .map(|r| r.public_key);

        if miner_public_key.is_none() {
            eprintln!(
                "Invalid submission: account_key {:?} not found.",
                hex::encode(&account_key)
            );
            continue;
        }

        let recomputed_hash = CpuMiner::generate_argon2_hash_with_params(
            &format!("{:?}:{:?}", account_key, nonce),
            &salt,
            &mining_params(),
        );

        if recomputed_hash != reward.hash {
            eprintln!("Hash mismatch for miner: {:?}", hex::encode(&account_key));
            continue;
        }

        let hash_array: [u8; 32] = match recomputed_hash.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => {
                eprintln!("Hash should be 32 bytes.");
                continue;
            }
        };
        let leading_zero_bits = CpuMiner::count_leading_zero_bits(&hash_array);

        // Miner reward = 2^(DIFFICULTY)
        let mut reward_amount: i64 = num_traits::pow(2, DIFFICULTY.try_into().unwrap());

        if leading_zero_bits >= DIFFICULTY {
            // Update supply and check max supply
            let supply = sqlx::query!(
                "SELECT circulating_supply, max_supply FROM supply LIMIT 1"
            )
            .fetch_one(&mut *dbtx)
            .await?;

            if supply.circulating_supply >= supply.max_supply {
                eprintln!("Max supply reached. No reward issued.");
                continue;
            }

            let available = supply.max_supply - supply.circulating_supply;
            if available < reward_amount {
                reward_amount = available;
            }

            if reward_amount <= 0 {
                eprintln!("No available supply for rewards.");
                continue;
            }

            // Update miner balance
            sqlx::query!(
                "UPDATE account_keys SET balance = balance + $1 WHERE account_key = $2",
                reward_amount,
                &account_key
            )
            .execute(&mut *dbtx)
            .await?;

            // Update circulating supply
            sqlx::query!(
                "UPDATE supply SET circulating_supply = circulating_supply + $1",
                reward_amount
            )
            .execute(&mut *dbtx)
            .await?;

            eprintln!(
                "Successfully rewarded miner: {:?} with amount: {}",
                hex::encode(&account_key),
                reward_amount
            );

            // If websockets are available, broadcast new supply + miner's new balance
            if let Some(bc) = &ws_broadcast {
                // 1) fetch updated supply
                let new_supply = supply.circulating_supply + reward_amount;

                // 2) fetch updated miner balance
                let updated_miner_balance = sqlx::query_scalar!(
                    "SELECT balance FROM account_keys WHERE account_key = $1",
                    &account_key
                )
                .fetch_one(&mut *dbtx)
                .await?;

                // broadcast supply update
                let _ = bc.send(json!({
                    "type": "supply_update",
                    "new_circulating_supply": new_supply
                }));

                // broadcast miner's balance update
                let _ = bc.send(json!({
                    "type": "balance_update",
                    "account_key": hex::encode(&account_key),
                    "new_balance": updated_miner_balance,
                }));
            }
        } else {
            eprintln!(
                "Hash failed difficulty check for miner: {:?}",
                hex::encode(&account_key)
            );
        }
    }

    dbtx.commit().await?;
    Ok(())
}

/// Periodically compute a global state root and store in DB.
async fn compute_and_store_global_root(pool: &PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let account_hashes =
        sqlx::query!("SELECT account_hash FROM account_keys ORDER BY account_key ASC")
            .fetch_all(pool)
            .await?;

    let supply = sqlx::query!("SELECT circulating_supply, max_supply FROM supply LIMIT 1")
        .fetch_one(pool)
        .await?;

    let mut data = Vec::new();
    data.extend_from_slice(&supply.circulating_supply.to_be_bytes());
    data.extend_from_slice(&supply.max_supply.to_be_bytes());

    for ah in account_hashes {
        data.extend_from_slice(&ah.account_hash);
    }

    let global_root = blake3::hash(&data);
    let global_bytes = global_root.as_bytes();

    sqlx::query!("INSERT INTO global_state_roots (root) VALUES ($1)", global_bytes)
        .execute(pool)
        .await?;

    println!("Updated global state root: {:?}", hex::encode(global_bytes));
    Ok(())
}

// Single-sig per transaction. For large batches, see "verify_batch".
async fn validate_transaction(pool: &PgPool, tx: &TransactionData) -> bool {
    // 1) Trivial checks
    if tx.sender_key.is_empty() || tx.receiver_key.is_empty() || tx.amount <= 0 {
        return false;
    }

    // 2) Fetch the 32-byte Ed25519 public key from the DB
    let record = match sqlx::query!(
        r#"
        SELECT a.public_key
        FROM accounts a
        JOIN account_keys ak ON a.public_key = ak.public_key
        WHERE ak.account_key = $1
        "#,
        &tx.sender_key
    )
    .fetch_one(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to find sender's public_key: {:?}", e);
            return false;
        }
    };

    if record.public_key.len() != 32 {
        eprintln!("Sender's public_key is not 32 bytes!");
        return false;
    }

    let pk_array: [u8; 32] = match record.public_key.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => {
            eprintln!("Could not convert public_key to [u8; 32]");
            return false;
        }
    };

    let verifying_key = match VerifyingKey::from_bytes(&pk_array) {
        Ok(vk) => vk,
        Err(e) => {
            eprintln!("Invalid Ed25519 public key: {:?}", e);
            return false;
        }
    };

    // 3) Rebuild the message
    let mut message = Vec::new();
    message.extend_from_slice(&tx.sender_key);
    message.extend_from_slice(&tx.receiver_key);
    message.extend_from_slice(&tx.amount.to_be_bytes());
    message.extend_from_slice(&tx.nonce);

    // 4) Parse signature
    if tx.signature.len() != 64 {
        eprintln!("Signature must be 64 bytes, got {}", tx.signature.len());
        return false;
    }
    let sig_array: [u8; 64] = match tx.signature.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => {
            eprintln!("Could not convert signature to [u8; 64]");
            return false;
        }
    };
    let signature = match Signature::try_from(&sig_array[..]) {
        Ok(sig) => sig,
        Err(e) => {
            eprintln!("Invalid signature bytes: {:?}", e);
            return false;
        }
    };

    // 5) Verify
    verifying_key.verify(&message, &signature).is_ok()
}

// -----------------------------------------------------
// OPTIONAL: Using verify_batch for Ed25519
// -----------------------------------------------------
//
// If you want to do "batch signature verification," you can gather
// all (message, signature, verifying_key) in a single pass, then call
// something like `ed25519_dalek::verify_batch(...)`. This can be
// faster for large batches. See the Ed25519-dalek docs for details.
//
// Typically you'd do something like:
//   let messages: Vec<_> = ...
//   let signatures: Vec<ed25519::Signature> = ...
//   let verifying_keys: Vec<VerifyingKey> = ...
//
//   match verify_batch(&messages_as_slices[..], &signatures[..], &verifying_keys[..]) {
//       Ok(_) => { /* all good */ }
//       Err(e) => eprintln!("Batch signature verify failed: {:?}", e),
//   }
//
// Then finalize those that pass (or discard if any fail).
