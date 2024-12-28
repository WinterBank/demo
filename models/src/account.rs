// models/src/account.rs

use serde::Serialize;
use sqlx::PgPool;
use std::result::Result;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use argon2::{password_hash::{SaltString, PasswordHasher}, Argon2};
use crate::utils::encrypt_private_key;

#[derive(Serialize, sqlx::FromRow, Debug)]
pub struct Account {
    pub public_key: [u8; 32],
    pub name: String,
    pub encrypted_private_key: Vec<u8>,
    pub private_key_nonce: Vec<u8>,
    pub kdf_salt: Vec<u8>,
    pub kdf_iterations: i32,
    pub created_at: chrono::NaiveDateTime,
}

impl Account {
    pub async fn insert(pool: &PgPool, account: Account) -> Result<(), sqlx::Error> {
        sqlx::query!(
            "INSERT INTO accounts (public_key, name, encrypted_private_key, private_key_nonce, kdf_salt, kdf_iterations, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &account.public_key,
            &account.name,
            &account.encrypted_private_key,
            &account.private_key_nonce,
            &account.kdf_salt,
            account.kdf_iterations,
            account.created_at
        )
        .execute(pool)
        .await?;
        Ok(())
    }
}

pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut csprng = OsRng;

    // Generate a new signing key
    let signing_key = SigningKey::generate(&mut csprng);

    // Get the verifying (public) key
    let verifying_key = signing_key.verifying_key();

    (signing_key, verifying_key)
}

pub fn generate_account_key(public_key: &[u8]) -> [u8; 16] {
    let hash = blake3::hash(public_key);
    hash.as_bytes()[..16].try_into().unwrap() // Truncate to 16 bytes
}

pub fn hash_password(password: &str) -> [u8; 32] {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .hash
        .unwrap();

    let hash_bytes = hash.as_bytes();
    let mut output = [0u8; 32];
    output.copy_from_slice(hash_bytes);
    output
}

pub fn create_new_account(name: String, password: String) -> (Account, [u8; 16]) {
    let (signing_key, verifying_key) = generate_keypair();

    let public_key = verifying_key.to_bytes();
    let private_key = signing_key.to_bytes();
    let main_account_key = generate_account_key(&public_key);

    let (encrypted_private_key, nonce, salt, kdf_iterations) =
        encrypt_private_key(&password, &private_key);

    let account = Account {
        public_key,
        name,
        encrypted_private_key: encrypted_private_key,
        private_key_nonce: nonce,
        kdf_salt: salt,
        kdf_iterations,
        created_at: chrono::Local::now().naive_local(),
    };

    (account, main_account_key)
}