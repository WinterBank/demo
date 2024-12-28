// wallet_core/src/routes.rs

use anyhow::{Result, anyhow};
use log::{info, error};
use gloo_net::http::Request;
use serde::{Deserialize, Serialize};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use async_std::task;
use ed25519_dalek::{
    SigningKey, VerifyingKey, Signature, Signer,
};
use rand::rngs::OsRng;

use crate::encryption::*;

/// A convenient client to interact with the WinterBank API.
/// You can store additional configuration here (e.g., API tokens).
pub struct WalletClient {
    api_url: String,
}

/// Basic structure to hold encrypted private key info that the client
/// might keep in local storage (e.g. browser localStorage or mobile DB).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncryptedKeyMaterial {
    pub public_key: [u8; 32],        // The verifying key
    pub encrypted_private_key: Vec<u8>,
    pub private_key_nonce: Vec<u8>,
    pub kdf_salt: Vec<u8>,
    pub kdf_iterations: u32,
}

/// Transaction data that WinterBank expects for a **signed** transaction.
/// This parallels your `TransactionData` on the server side.
#[derive(Serialize, Deserialize, Debug)]
pub struct SignedTransaction {
    pub sender_key: Vec<u8>,
    pub receiver_key: Vec<u8>,
    pub amount: i64,
    pub signature: Vec<u8>,
    pub nonce: [u8; 8],
}

/// Example: Response shape from WinterBank for transaction submission.
#[derive(Serialize, Deserialize, Debug)]
pub struct TransactionResponse {
    pub message: String,
    pub transaction_id: String,
}

/// Example: A minimal account creation request structure
/// if your server expects full encryption data in the body.
#[derive(Serialize)]
pub struct CreateAccountPayload {
    pub public_key: [u8; 32],
    pub encrypted_private_key: Vec<u8>,
    pub private_key_nonce: Vec<u8>,
    pub kdf_salt: Vec<u8>,
    pub kdf_iterations: u32,
    pub name: String,
}

/// Example: Circulating supply response
#[derive(Deserialize)]
pub struct SupplyResponse {
    pub circulating_supply: i64,
}

/// Example: Mining params from the server
#[derive(Deserialize)]
pub struct MiningParams {
    pub difficulty: u64,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub output_len: usize,
}

impl WalletClient {
    /// Construct a new wallet client with a given API URL.
    /// The `api_url` should be something like "http://localhost:8080"
    pub fn new(api_url: &str) -> Self {
        Self {
            api_url: api_url.to_string(),
        }
    }

    // =========================================================================
    // 1. Key Management
    // =========================================================================

    /// Generate a brand new signing key & verifying key (Ed25519) plus
    /// encrypt the private key using Argon2 for password-based encryption.
    /// 
    /// Returns `(EncryptedKeyMaterial, [u8; 16])` where the second item is
    /// the 16-byte "account_key" if you want to treat it like your main account key.
    /// 
    /// In many scenarios, you only need the `EncryptedKeyMaterial` (to store locally)
    /// and the server never sees your password or raw private key.
    pub fn generate_and_encrypt_keys(
        name: &str,
        password: &str,
    ) -> (EncryptedKeyMaterial, [u8; 16]) {
        // Generate Ed25519 keypair
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        // Locally encrypt the private key with user’s password:
        let (encrypted_private_key, nonce, salt, iterations) =
            encrypt_private_key(password, &signing_key.to_bytes());

        // Derive the 16-byte account key from the public key
        let account_key = generate_account_key(&verifying_key.to_bytes());

        let encrypted_km = EncryptedKeyMaterial {
            public_key: verifying_key.to_bytes(),
            encrypted_private_key,
            private_key_nonce: nonce,
            kdf_salt: salt,
            kdf_iterations: iterations,
        };

        (encrypted_km, account_key)
    }

    /// Decrypt the locally-stored private key using the user’s password.
    /// 
    /// Returns a `SigningKey` if successful.
    pub fn decrypt_signing_key(
        password: &str,
        ekm: &EncryptedKeyMaterial,
    ) -> Result<SigningKey> {
        let decrypted = decrypt_private_key(
            password,
            &ekm.encrypted_private_key,
            &ekm.private_key_nonce,
            &ekm.kdf_salt,
            ekm.kdf_iterations,
        )?;
        if decrypted.len() != 32 {
            return Err(anyhow!("Private key must be 32 bytes for Ed25519."));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&decrypted);
        Ok(SigningKey::from_bytes(&arr))
    }

    // =========================================================================
    // 2. API Calls for Accounts
    // =========================================================================

    /// Example function to create an account on the server without ever
    /// sending the user’s password in plaintext.  
    /// **Requires** your server to accept a payload with all encryption info.
    ///
    /// (In your current server code, `/accounts` expects name & password—but
    /// you could adapt it to accept this new approach.)
    pub async fn create_account_on_server(
        &self,
        name: &str,
        ekm: &EncryptedKeyMaterial,
    ) -> Result<()> {
        let payload = CreateAccountPayload {
            public_key: ekm.public_key,
            encrypted_private_key: ekm.encrypted_private_key.clone(),
            private_key_nonce: ekm.private_key_nonce.clone(),
            kdf_salt: ekm.kdf_salt.clone(),
            kdf_iterations: ekm.kdf_iterations,
            name: name.to_string(),
        };

        let url = format!("{}/accounts/new", self.api_url);
        let resp = Request::post(&url)
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&payload)?)?
            .send()
            .await?;
        
        if resp.ok() {
            Ok(())
        } else {
            let txt = resp.text().await?;
            Err(anyhow!("Failed to create account: {}", txt))
        }
    }

    /// Example function to create a sub-account. This approach still requires
    /// you to prove ownership by decrypting your main private key locally.
    /// The server code might need a new route that accepts a signature proof
    /// instead of a raw password.
    pub async fn create_sub_account_on_server(
        &self,
        main_encrypted: &EncryptedKeyMaterial,
        password: &str,
        sub_name: &str,
    ) -> Result<()> {
        let url = format!("{}/accounts/{}/subaccounts", self.api_url, sub_name);
        let resp = Request::post(&url)
            .header("Content-Type", "application/json")
            .send()
            .await?;
    
        if resp.ok() {
            Ok(())
        } else {
            let txt = resp.text().await?;
            Err(anyhow!("HTTP error: {}", txt))
        }
    }    

    // =========================================================================
    // 3. Get Circulating Supply
    // =========================================================================

    pub async fn get_circulating_supply(&self) -> Result<i64> {
        let url = format!("{}/supply", self.api_url);
        let resp = Request::get(&url)
            .send()
            .await?;
    
        if resp.ok() {
            let supply_val = resp.json::<SupplyResponse>().await?;
            Ok(supply_val.circulating_supply)
        } else {
            let txt = resp.text().await?;
            Err(anyhow!("Failed to fetch supply: {}", txt))
        }
    }    

    // =========================================================================
    // 4. Transactions: Offline Signing + Submission
    // =========================================================================

    /// Create and sign a transaction locally.  
    /// Returns a `SignedTransaction` **ready to submit** to WinterBank.
    pub fn sign_transaction(
        &self,
        sender_key_16: [u8; 16],
        receiver_key_16: [u8; 16],
        amount: i64,
        signing_key: &SigningKey,
    ) -> SignedTransaction {
        use rand::RngCore;

        // Build the message for signing
        // (Mirrors the server's approach in `validate_transaction`)
        let mut nonce = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut nonce);

        let mut message = Vec::new();
        message.extend_from_slice(&sender_key_16);
        message.extend_from_slice(&receiver_key_16);
        message.extend_from_slice(&amount.to_be_bytes());
        message.extend_from_slice(&nonce);

        let signature = signing_key.sign(&message);

        SignedTransaction {
            sender_key: sender_key_16.to_vec(),
            receiver_key: receiver_key_16.to_vec(),
            amount,
            signature: signature.to_bytes().to_vec(),
            nonce,
        }
    }

    /// Submit the already-signed transaction to WinterBank.
    /// Expects a server route (e.g. `POST /transactions/new`) that
    /// verifies the Ed25519 signature and ensures the sender has funds.
    pub async fn submit_transaction(
        &self,
        tx: &SignedTransaction,
    ) -> Result<()> {
        let url = format!("{}/transactions/new", self.api_url);
        let resp = Request::post(&url)
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(tx)?)?
            .send()
            .await?;
        
        if resp.ok() {
            Ok(())
        } else {
            let txt = resp.text().await?;
            Err(anyhow!("Failed to submit transaction: {}", txt))
        }
    }

    /// Example function to retrieve **all** transactions from WinterBank.
    /// You might want filters, pagination, etc. in production.
    pub async fn get_transactions(&self) -> Result<serde_json::Value> {
        let url = format!("{}/transactions", self.api_url);
        let resp = Request::get(&url)
            .send()
            .await?;
    
        if resp.ok() {
            let json_val = resp.json::<serde_json::Value>().await?;
            Ok(json_val)
        } else {
            let txt = resp.text().await?;
            Err(anyhow!("Failed to get transactions: {}", txt))
        }
    }

    /// Retreive All Transactions for a single user
    pub async fn get_user_transactions(&self, identifier: &str) -> Result<serde_json::Value> {
        let url = format!("{}/accounts/{}/transactions", self.api_url, identifier);
        let resp = Request::get(&url).send().await?;

        if resp.ok() {
            let json_val = resp.json::<serde_json::Value>().await?;
            Ok(json_val)
        } else {
            let txt = resp.text().await?;
            Err(anyhow!("Failed to get user transactions: {}", txt))
        }
    }
}