// api/src/routes.rs

use actix_web::{web, post, get, HttpResponse, Responder};
use sqlx::{PgPool, types::chrono};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::sync::Arc;
use redis::Client as RedisClient;
use rand::RngCore;

use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};

use models::account::{Account, create_new_account, generate_account_key};
use models::utils::{decrypt_private_key};
use crate::utils::*;
use crate::mining_params::{mining_params, DIFFICULTY};


// =============================================================================
// Existing Structures
// =============================================================================

#[derive(Deserialize)]
pub struct CreateAccountRequest {
    pub name: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct CreateSubAccountRequest {
    pub sub_name: String,
    pub password: String,
}

#[derive(serde::Serialize)]
pub struct MiningParamsResponse {
    pub difficulty: u64,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub output_len: usize,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MiningSubmission {
    pub account_key: Vec<u8>,
    pub nonce: u64,
    pub hash: Vec<u8>,
    pub salt: Vec<u8>,
}

/// DEPRECATED: This request struct sends a plaintext password for transaction creation.
#[derive(Debug, Deserialize)]
pub struct TransactionRequest {
    pub sender: String,
    pub receiver: String,
    pub amount: i64,
    pub password: String,
}

/// The server STILL uses this struct to store a transaction in the DB,
/// or for older routes that finalize transactions. 
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionData {
    pub sender_key: Vec<u8>,
    pub receiver_key: Vec<u8>,
    pub amount: i64,
    pub signature: Vec<u8>,
    pub nonce: [u8; 8],
}

#[derive(sqlx::FromRow, serde::Serialize)]
pub struct TransactionRecord {
    pub id: Vec<u8>,
    pub sender_key: Vec<u8>,
    pub receiver_key: Vec<u8>,
    pub amount: i64,
    pub signature: Vec<u8>,
    pub created_at: chrono::NaiveDateTime,
}

// =============================================================================
// Name Validation Helper
// =============================================================================

fn validate_name(name: &str) -> Result<(), HttpResponse> {
    let length = name.chars().count();
    if length < 3 || length > 32 {
        return Err(HttpResponse::BadRequest().body("Name must be between 3 and 32 characters"));
    }

    if name.contains(' ') {
        return Err(HttpResponse::BadRequest().body("Name cannot contain spaces"));
    }

    Ok(())
}

// =============================================================================
// 1) DEPRECATED Endpoint: Create Account with Plaintext Password
// =============================================================================

/// DEPRECATED. Historically creates an account with a plaintext password.  
/// Kept for backward compatibility. Use `/accounts/new` for client-side encryption.
#[post("/accounts")]
async fn create_account(
    pool: web::Data<PgPool>,
    account_request: web::Json<CreateAccountRequest>,
) -> impl Responder {
    if let Err(resp) = validate_name(&account_request.name) {
        return resp;
    }

    let existing_account = sqlx::query!(
        "SELECT name FROM accounts WHERE name = $1",
        account_request.name
    )
    .fetch_optional(pool.get_ref())
    .await;

    if let Ok(Some(_)) = existing_account {
        return HttpResponse::BadRequest().body("Account name already exists");
    }

    // This calls `create_new_account` on the server, generating the private key here 
    // and storing an encrypted version in the DB. 
    // (Server-based key generation is no longer recommended.)
    let (account, main_account_key) = create_new_account(
        account_request.name.clone(),
        account_request.password.clone(),
    );

    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    // Insert into `accounts`
    let res = sqlx::query!(
        "INSERT INTO accounts (public_key, name, encrypted_private_key, 
                               private_key_nonce, kdf_salt, kdf_iterations, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
        &account.public_key,
        &account.name,
        &account.encrypted_private_key,
        &account.private_key_nonce,
        &account.kdf_salt,
        account.kdf_iterations,
        account.created_at
    )
    .execute(&mut *tx)
    .await;

    if res.is_err() {
        let _ = tx.rollback().await;
        return HttpResponse::InternalServerError().finish();
    }

    // Insert into `account_keys`
    let res = sqlx::query!(
        "INSERT INTO account_keys (public_key, sub_name, account_key, balance) 
         VALUES ($1, 'main', $2, 0)",
        &account.public_key,
        &main_account_key
    )
    .execute(&mut *tx)
    .await;

    if res.is_err() {
        let _ = tx.rollback().await;
        return HttpResponse::InternalServerError().finish();
    }

    match tx.commit().await {
        Ok(_) => HttpResponse::Created().finish(),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

// =============================================================================
// 2) NEW Endpoint: Create Account with Client-Side Encryption
// =============================================================================

/// Struct that the client will send if they’ve already encrypted their private key
/// using Argon2 or XChaCha20 on the **client side**.
#[derive(Debug, Deserialize)]
pub struct NewAccountRequest {
    pub public_key: Vec<u8>,              // 32 bytes (Ed25519 verifying key)
    pub encrypted_private_key: Vec<u8>,   // e.g. XChaCha20-Poly1305 ciphertext
    pub private_key_nonce: Vec<u8>,       // e.g. 24 bytes of XChaCha20 nonce
    pub kdf_salt: Vec<u8>,                // Argon2 salt
    pub kdf_iterations: i32,              // Argon2 t_cost or iteration count
    pub name: String,                     // user-chosen name
}

#[post("/accounts/new")]
async fn create_account_new(
    pool: web::Data<PgPool>,
    new_account: web::Json<NewAccountRequest>,
) -> impl Responder {
    // Basic name checks
    if let Err(resp) = validate_name(&new_account.name) {
        return resp;
    }

    // Check if name already exists
    let existing_account = sqlx::query!(
        "SELECT name FROM accounts WHERE name = $1",
        new_account.name
    )
    .fetch_optional(pool.get_ref())
    .await;

    if let Ok(Some(_)) = existing_account {
        return HttpResponse::BadRequest().body("Account name already exists");
    }

    // 16-byte main account_key derived from the public_key
    let main_account_key = generate_account_key(&new_account.public_key);

    // The timestamp
    let created_at = chrono::Local::now().naive_local();

    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    // Insert into `accounts`
    let res = sqlx::query!(
        "INSERT INTO accounts 
         (public_key, name, encrypted_private_key, private_key_nonce, 
          kdf_salt, kdf_iterations, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
        &new_account.public_key,
        &new_account.name,
        &new_account.encrypted_private_key,
        &new_account.private_key_nonce,
        &new_account.kdf_salt,
        new_account.kdf_iterations,
        created_at
    )
    .execute(&mut *tx)
    .await;

    if res.is_err() {
        let _ = tx.rollback().await;
        return HttpResponse::InternalServerError().finish();
    }

    // Insert the "main" sub-account row in `account_keys`
    let res = sqlx::query!(
        "INSERT INTO account_keys (public_key, sub_name, account_key, balance) 
         VALUES ($1, 'main', $2, 0)",
        &new_account.public_key,
        &main_account_key
    )
    .execute(&mut *tx)
    .await;

    if res.is_err() {
        let _ = tx.rollback().await;
        return HttpResponse::InternalServerError().finish();
    }

    match tx.commit().await {
        Ok(_) => HttpResponse::Created().finish(),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

// =============================================================================
// 3) Create Sub-Account (still depends on password or partial approach?)
// =============================================================================

#[post("/accounts/{main_name}/subaccounts")]
async fn create_sub_account(
    pool: web::Data<PgPool>,
    path: web::Path<String>,
    sub_account_request: web::Json<CreateSubAccountRequest>,
) -> impl Responder {
    let main_name = path.into_inner();
    let sub_name = &sub_account_request.sub_name;
    let password = &sub_account_request.password;

    if let Err(resp) = validate_name(&main_name) {
        return resp;
    }
    if let Err(resp) = validate_name(&sub_name) {
        return resp;
    }

    // Fetch main account public_key and encryption details
    let main_account = match sqlx::query!(
        "SELECT public_key, encrypted_private_key, private_key_nonce, kdf_salt, kdf_iterations
         FROM accounts WHERE name = $1",
        main_name
    )
    .fetch_optional(pool.get_ref())
    .await {
        Ok(Some(a)) => a,
        Ok(None) => return HttpResponse::BadRequest().body("Main account not found"),
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    // Attempt to decrypt or verify password
    let test_decrypt = decrypt_private_key(
        password,
        &main_account.encrypted_private_key,
        &main_account.private_key_nonce,
        &main_account.kdf_salt,
        main_account.kdf_iterations
    );

    if test_decrypt.is_err() {
        return HttpResponse::Unauthorized().body("Invalid password or decryption failed");
    }

    // Check if sub_name already exists
    let existing_sub = sqlx::query!(
        "SELECT sub_name FROM account_keys WHERE public_key = $1 AND sub_name = $2",
        &main_account.public_key,
        sub_name
    )
    .fetch_optional(pool.get_ref())
    .await;

    if let Ok(Some(_)) = existing_sub {
        return HttpResponse::BadRequest().body("Sub-account name already exists");
    }

    // Generate a new account_key for this subaccount
    let mut pub_plus_sub = main_account.public_key.clone();
    pub_plus_sub.extend_from_slice(sub_name.as_bytes());
    let sub_account_key = generate_account_key(&pub_plus_sub);

    let res = sqlx::query!(
        "INSERT INTO account_keys (public_key, sub_name, account_key, balance) 
         VALUES ($1, $2, $3, 0)",
        &main_account.public_key,
        sub_name,
        &sub_account_key
    )
    .execute(pool.get_ref())
    .await;

    match res {
        Ok(_) => {
            let info = serde_json::json!({
                "public_key": hex::encode(&main_account.public_key),
                "sub_name": sub_name,
                "account_key": hex::encode(&sub_account_key),
                "balance": 0,
                "full_name": format!("{}.{}", sub_name, main_name)
            });
            HttpResponse::Created().json(info)
        }
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

// =============================================================================
// 4) Get Accounts, Single Account, Mining Params, Supply
// =============================================================================

#[get("/accounts")]
pub async fn get_accounts(pool: web::Data<PgPool>) -> impl Responder {
    let result = sqlx::query_as::<_, Account>("SELECT * FROM accounts")
        .fetch_all(pool.get_ref())
        .await;

    match result {
        Ok(accounts) => HttpResponse::Ok().json(accounts),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

#[get("/accounts/{identifier}")]
pub async fn get_account_by_identifier(
    pool: web::Data<PgPool>,
    path: web::Path<String>,
) -> impl Responder {
    let identifier = path.into_inner();
    let parts: Vec<&str> = identifier.split('.').collect();

    if parts.len() == 2 {
        // sub_name.main_name format
        let sub_name = parts[0];
        let main_name = parts[1];

        let public_key_opt = sqlx::query!(
            "SELECT public_key FROM accounts WHERE name = $1",
            main_name
        )
        .fetch_optional(pool.get_ref())
        .await;

        let public_key = match public_key_opt {
            Ok(Some(rec)) => rec.public_key,
            Ok(None) => return HttpResponse::NotFound().body("Main account not found"),
            Err(_) => return HttpResponse::InternalServerError().finish(),
        };

        let ak_opt = sqlx::query!(
            "SELECT account_key, balance FROM account_keys 
             WHERE public_key = $1 AND sub_name = $2",
            &public_key,
            sub_name
        )
        .fetch_optional(pool.get_ref())
        .await;

        match ak_opt {
            Ok(Some(rec)) => {
                let info = serde_json::json!({
                    "public_key": hex::encode(&public_key),
                    "sub_name": sub_name,
                    "account_key": hex::encode(&rec.account_key),
                    "balance": rec.balance,
                    "full_name": format!("{}.{}", sub_name, main_name)
                });
                HttpResponse::Ok().json(info)
            }
            Ok(None) => HttpResponse::NotFound().body("Sub-account not found"),
            Err(_) => HttpResponse::InternalServerError().finish(),
        }
    } else {
        // No dot => either main account name or hex-encoded account_key
        if let Ok(decoded) = hex::decode(&identifier) {
            if decoded.len() == 16 {
                // It's a 16-byte account_key
                let ak_opt = sqlx::query!(
                    "SELECT public_key, sub_name, balance 
                     FROM account_keys WHERE account_key = $1",
                    &decoded
                )
                .fetch_optional(pool.get_ref())
                .await;

                match ak_opt {
                    Ok(Some(rec)) => {
                        let main_name_opt = sqlx::query!(
                            "SELECT name FROM accounts WHERE public_key = $1",
                            &rec.public_key
                        )
                        .fetch_optional(pool.get_ref())
                        .await;

                        let main_name_opt = match main_name_opt {
                            Ok(val) => val,
                            Err(_) => return HttpResponse::InternalServerError().finish(),
                        };

                        if let Some(main_account) = main_name_opt {
                            let full_name = if rec.sub_name == "main" {
                                main_account.name
                            } else {
                                format!("{}.{}", rec.sub_name, main_account.name)
                            };
                            let info = serde_json::json!({
                                "public_key": hex::encode(&rec.public_key),
                                "sub_name": rec.sub_name,
                                "account_key": hex::encode(&decoded),
                                "balance": rec.balance,
                                "full_name": full_name
                            });
                            return HttpResponse::Ok().json(info);
                        } else {
                            return HttpResponse::NotFound().body("Associated main account not found");
                        }
                    }
                    Ok(None) => return HttpResponse::NotFound().body("account_key not found"),
                    Err(_) => return HttpResponse::InternalServerError().finish(),
                }
            }
        }

        // Otherwise treat as main account name
        let main_account_opt = sqlx::query!(
            "SELECT public_key, name, encrypted_private_key, 
                    private_key_nonce, kdf_salt, kdf_iterations, created_at 
             FROM accounts WHERE name = $1",
            identifier
        )
        .fetch_optional(pool.get_ref())
        .await;

        let main_account_opt = match main_account_opt {
            Ok(val) => val,
            Err(_) => return HttpResponse::InternalServerError().finish(),
        };

        match main_account_opt {
            Some(rec) => {
                let main_key_opt = sqlx::query!(
                    "SELECT account_key, balance FROM account_keys 
                     WHERE public_key = $1 AND sub_name = 'main'",
                    &rec.public_key
                )
                .fetch_one(pool.get_ref())
                .await;
            
                let main_key_opt = match main_key_opt {
                    Ok(val) => val,
                    Err(_) => return HttpResponse::InternalServerError().finish(),
                };
            
                let info = serde_json::json!({
                    "public_key": hex::encode(&rec.public_key),
                    "name": rec.name,
                    "account_key": hex::encode(&main_key_opt.account_key),
                    "balance": main_key_opt.balance,
            
                    // Include these so the front-end can parse them for sign-in
                    "encrypted_private_key": hex::encode(&rec.encrypted_private_key),
                    "private_key_nonce": hex::encode(&rec.private_key_nonce),
                    "kdf_salt": hex::encode(&rec.kdf_salt),
                    "kdf_iterations": rec.kdf_iterations
                });
                HttpResponse::Ok().json(info)
            }            
            None => HttpResponse::NotFound().body("Account not found"),
        }
    }
}

#[get("/mining_params")]
pub async fn get_mining_params() -> impl Responder {
    let params = mining_params();
    HttpResponse::Ok().json(MiningParamsResponse {
        difficulty: DIFFICULTY,
        m_cost: params.m_cost(),
        t_cost: params.t_cost(),
        p_cost: params.p_cost(),
        output_len: 32,
    })
}

#[post("/submit_mining_result")]
async fn submit_mining_result(
    redis_client: web::Data<Arc<RedisClient>>,
    submission: web::Json<MiningSubmission>,
) -> impl Responder {
    println!(
        "Received mining submission: account_key: {:?}, nonce: {}, hash: {:?}, salt: {:?}",
        hex::encode(&submission.account_key),
        submission.nonce,
        hex::encode(&submission.hash),
        hex::encode(&submission.salt)
    );

    if submission.account_key.len() != 16 {
        return HttpResponse::BadRequest().body("Invalid account key length.");
    }
    if submission.hash.len() != 32 {
        return HttpResponse::BadRequest().body("Invalid hash length.");
    }

    match enqueue_mining_submission(
        redis_client.get_ref(),
        submission.account_key.clone(),
        submission.nonce,
        submission.hash.clone(),
        submission.salt.clone(),
    )
    .await
    {
        Ok(_) => HttpResponse::Ok().body("Mining result accepted."),
        Err(err) => {
            eprintln!("Failed to enqueue mining submission: {}", err);
            HttpResponse::InternalServerError().body("Failed to process mining result.")
        }
    }
}

#[get("/supply")]
async fn get_circulating_supply(pool: web::Data<PgPool>) -> impl Responder {
    match sqlx::query!("SELECT circulating_supply FROM supply LIMIT 1")
        .fetch_one(pool.get_ref())
        .await
    {
        Ok(record) => {
            // Return an object: {"circulating_supply": <value>}
            use serde_json::json;
            let body = json!({ "circulating_supply": record.circulating_supply });
            HttpResponse::Ok().json(body)
        }
        Err(_) => HttpResponse::InternalServerError().body("Failed to fetch supply"),
    }
}

// =============================================================================
// 5) DEPRECATED Endpoint: Create Transaction with Plaintext Password
// =============================================================================

/// DEPRECATED.  Instead, use `/transactions/new` with a fully signed transaction.
#[post("/transactions")]
pub async fn create_transaction(
    pool: web::Data<PgPool>,
    req: web::Json<TransactionRequest>,
    redis_client: web::Data<Arc<RedisClient>>,
) -> impl Responder {
    let sender_identifier = &req.sender;
    let receiver_identifier = &req.receiver;
    let amount = req.amount;

    if amount <= 0 {
        return HttpResponse::BadRequest().body("Amount must be greater than zero.");
    }

    // Resolve both accounts
    let sender_key = match resolve_account_key(pool.get_ref(), sender_identifier).await {
        Ok(key) => key,
        Err(err) => return HttpResponse::BadRequest().body(err),
    };
    let receiver_key = match resolve_account_key(pool.get_ref(), receiver_identifier).await {
        Ok(key) => key,
        Err(err) => return HttpResponse::BadRequest().body(err),
    };
    if sender_key == receiver_key {
        return HttpResponse::BadRequest().body("Sender and receiver cannot be the same.");
    }

    // Retrieve & decrypt the sender’s private key using the plaintext password (deprecated approach).
    let account = match sqlx::query!(
        "SELECT a.encrypted_private_key, a.private_key_nonce, a.kdf_salt, a.kdf_iterations
         FROM accounts a
         JOIN account_keys ak ON a.public_key = ak.public_key
         WHERE ak.account_key = $1",
        &sender_key
    )
    .fetch_one(pool.get_ref())
    .await {
        Ok(record) => record,
        Err(_) => return HttpResponse::BadRequest().body("Sender account not found."),
    };

    let private_key = match decrypt_private_key(
        &req.password,
        &account.encrypted_private_key,
        &account.private_key_nonce,
        &account.kdf_salt,
        account.kdf_iterations
    ) {
        Ok(pk) => pk,
        Err(_) => return HttpResponse::Unauthorized().body("Invalid password or decryption failed"),
    };

    if private_key.len() != 32 {
        return HttpResponse::InternalServerError().body("Invalid private key length");
    }
    let private_key_bytes: &[u8; 32] = match private_key.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => return HttpResponse::InternalServerError().body("Invalid private key length"),
    };

    // Sign the transaction
    let signing_key = SigningKey::from_bytes(private_key_bytes);
    let mut nonce = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut nonce);

    let mut message = Vec::new();
    message.extend_from_slice(&sender_key);
    message.extend_from_slice(&receiver_key);
    message.extend_from_slice(&amount.to_be_bytes());
    message.extend_from_slice(&nonce);

    let signature = signing_key.sign(&message);

    let transaction_id = compute_transaction_id(
        &sender_key,
        &receiver_key,
        amount,
        &signature.to_bytes(),
        &nonce,
    );

    // Build the transaction data
    let tx_data = TransactionData {
        sender_key: sender_key.to_vec(),
        receiver_key: receiver_key.to_vec(),
        amount,
        signature: signature.to_bytes().to_vec(),
        nonce,
    };

    let serialized_tx = match serde_json::to_vec(&tx_data) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize transaction: {:?}", e);
            return HttpResponse::InternalServerError().body("Failed to serialize transaction.");
        }
    };

    // Enqueue
    match enqueue_transaction(redis_client.get_ref(), &serialized_tx).await {
        Ok(_) => {
            println!("Enqueued transaction successfully.");
        },
        Err(e) => {
            eprintln!("Failed to enqueue transaction: {:?}", e);
            return HttpResponse::InternalServerError().body("Failed to enqueue transaction.");
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "message": "Transaction enqueued successfully.",
        "transaction_id": hex::encode(transaction_id)
    }))
}

// =============================================================================
// 6) NEW Endpoint: Create Transaction with a Fully Signed Payload
// =============================================================================

/// The client will sign the transaction locally using their Ed25519 private key.
/// They send the **already-signed** `TransactionData` below.
#[post("/transactions/new")]
pub async fn create_transaction_new(
    pool: web::Data<PgPool>,
    redis_client: web::Data<Arc<RedisClient>>,
    tx_data: web::Json<TransactionData>,
) -> impl Responder {
    // Validate the basic fields
    if tx_data.amount <= 0 {
        return HttpResponse::BadRequest().body("Amount must be greater than zero.");
    }
    if tx_data.sender_key == tx_data.receiver_key {
        return HttpResponse::BadRequest().body("Sender and receiver cannot be the same.");
    }
    if tx_data.signature.len() != 64 {
        return HttpResponse::BadRequest().body("Signature must be 64 bytes for Ed25519.");
    }

    // Verify that the sender account_key is recognized
    let sender_account = sqlx::query!(
        "SELECT a.public_key, ak.balance 
         FROM accounts a
         JOIN account_keys ak ON a.public_key = ak.public_key
         WHERE ak.account_key = $1",
        &tx_data.sender_key
    )
    .fetch_optional(pool.get_ref())
    .await;

    let sender_rec = match sender_account {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::BadRequest().body("Sender not found."),
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    // Rebuild the message that was presumably signed
    let mut message = Vec::new();
    message.extend_from_slice(&tx_data.sender_key);
    message.extend_from_slice(&tx_data.receiver_key);
    message.extend_from_slice(&tx_data.amount.to_be_bytes());
    message.extend_from_slice(&tx_data.nonce);

    // Convert public_key from DB (Vec<u8>) -> [u8; 32] -> Ed25519 verifying key
    if sender_rec.public_key.len() != 32 {
        return HttpResponse::InternalServerError().body("Public key in DB is not 32 bytes!");
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&sender_rec.public_key);
    let verifying_key = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(vk) => vk,
        Err(_) => return HttpResponse::BadRequest().body("Invalid Ed25519 public key."),
    };

    // Convert signature
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&tx_data.signature);
    let signature = match Signature::try_from(sig_arr.as_slice()) {
        Ok(sig) => sig,
        Err(_) => return HttpResponse::BadRequest().body("Invalid signature bytes."),
    };

    // Verify
    if verifying_key.verify(&message, &signature).is_err() {
        return HttpResponse::Unauthorized().body("Signature verification failed.");
    }

    // If desired, you can also check if the sender_rec.balance >= tx_data.amount 
    // before enqueueing. For now, we’ll let finalization handle it.

    // Serialize the transaction for queueing
    let serialized_tx = match serde_json::to_vec(&*tx_data) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize transaction: {:?}", e);
            return HttpResponse::InternalServerError().body("Failed to serialize transaction.");
        }
    };

    match enqueue_transaction(redis_client.get_ref(), &serialized_tx).await {
        Ok(_) => {
            println!("Enqueued transaction successfully (client-signed).");
        },
        Err(e) => {
            eprintln!("Failed to enqueue transaction: {:?}", e);
            return HttpResponse::InternalServerError().body("Failed to enqueue transaction.");
        }
    }

    // Optionally compute a quick transaction ID (like the older route does)
    let tx_id = compute_transaction_id(
        &tx_data.sender_key,
        &tx_data.receiver_key,
        tx_data.amount,
        &tx_data.signature,
        &tx_data.nonce,
    );

    HttpResponse::Ok().json(serde_json::json!({
        "message": "Transaction enqueued successfully.",
        "transaction_id": hex::encode(tx_id)
    }))
}

// =============================================================================
// 7) Get All Transactions
// =============================================================================

#[get("/transactions")]
pub async fn get_transactions(pool: web::Data<PgPool>) -> impl Responder {
    let result = sqlx::query_as::<_, TransactionRecord>(
        "SELECT id, sender_key, receiver_key, amount, signature, created_at 
         FROM transactions"
    )
    .fetch_all(pool.get_ref())
    .await;

    match result {
        Ok(transactions) => {
            let transactions: Vec<_> = transactions
                .into_iter()
                .map(|mut tx| {
                    // Convert `id` from Vec<u8> to hex string for readability
                    tx.id = hex::encode(tx.id).into_bytes(); 
                    tx
                })
                .collect();
            HttpResponse::Ok().json(transactions)
        }
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

// =============================================================================
// 7) Get Transactions For A Single Account
// =============================================================================

#[get("/accounts/{identifier}/transactions")]
pub async fn get_user_transactions(
    pool: web::Data<PgPool>,
    path: web::Path<String>,
) -> impl Responder {
    let identifier = path.into_inner();

    // 1) Resolve the 16-byte account_key from the user-supplied identifier,
    //    using your existing helper function:
    let account_key_16 = match resolve_account_key(pool.get_ref(), &identifier).await {
        Ok(k) => k,
        Err(e) => return HttpResponse::BadRequest().body(e),
    };

    // 2) Query DB for all transactions where sender_key = account_key or receiver_key = account_key
    let result = sqlx::query_as::<_, TransactionRecord>(
        r#"
        SELECT id, sender_key, receiver_key, amount, signature, created_at
        FROM transactions
        WHERE sender_key = $1 OR receiver_key = $1
        ORDER BY created_at DESC
        "#,
    )
    .bind(&account_key_16[..]) // we pass the 16-byte array as bytes
    .fetch_all(pool.get_ref())
    .await;

    match result {
        Ok(mut txs) => {
            // Convert the `id` from bytes to hex for readability, same as you do in `get_transactions`
            for tx in &mut txs {
                tx.id = hex::encode(&tx.id).into_bytes();
            }
            HttpResponse::Ok().json(txs)
        }
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}