// models/src/utils.rs

use aes_gcm::{aead::{Aead, KeyInit, OsRng}, Aes256Gcm, Nonce};
use rand::RngCore;
use argon2::{Argon2, Algorithm, Version, Params, password_hash::{Decimal, PasswordHasher, SaltString, Ident}};
use std::str;


/// Derive encryption key from password using Argon2 and encrypt the private_key using AES-GCM.
pub fn encrypt_private_key(password: &str, private_key: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>, i32) {
    // Argon2 parameters:
    // memory: 65536 KiB (64 MiB), iterations: 3, parallelism: 1, output length: 32 bytes
    let params = Params::new(65536, 3, 1, Some(32)).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone());

    // Generate random salt
    let salt = SaltString::generate(&mut OsRng);

    // Derive the key using hash_password_customized
    // Argon2id v=19 means version = 0x13 = decimal 19
    let password_hash = argon2
        .hash_password_customized(
            password.as_bytes(),
            Some(Ident::new("argon2id").unwrap()),
            Some(Decimal::from(19u32)),
            params,
            salt.as_salt()
        )
        .unwrap();

    let binding = password_hash.hash.unwrap();
    let hash_bytes = binding.as_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(hash_bytes);

    // Initialize AES-GCM with derived key
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();

    // Generate a random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the private key
    let ciphertext = cipher.encrypt(nonce, private_key).unwrap();

    // Store the salt in base64 form so we can reconstruct SaltString later
    let salt_b64 = salt.to_string();
    (
        ciphertext,
        nonce_bytes.to_vec(),
        salt_b64.as_bytes().to_vec(), // Store the b64 encoded salt
        3 // kdf_iterations as i32
    )
}

/// Decrypt the private key with the user's password
/// Assumes that `kdf_salt` was stored as the base64-encoded salt string.
pub fn decrypt_private_key(
    password: &str,
    encrypted_private_key: &[u8],
    nonce: &[u8],
    kdf_salt: &[u8],
    kdf_iterations: i32,
) -> Result<Vec<u8>, String> {
    let params = Params::new(65536, kdf_iterations as u32, 1, Some(32)).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone());

    // Decode the base64-encoded salt string
    let salt_b64 = str::from_utf8(kdf_salt).map_err(|e| e.to_string())?;
    let salt_string = SaltString::from_b64(salt_b64).map_err(|e| e.to_string())?;

    let password_hash = argon2
        .hash_password_customized(
            password.as_bytes(),
            Some(Ident::new("argon2id").unwrap()),
            Some(Decimal::from(19u32)),
            params,
            salt_string.as_salt() // Provide the salt as Salt<'_>
        )
        .map_err(|e| e.to_string())?;

    let binding = password_hash.hash.ok_or("No hash in password_hash")?;
    let hash_bytes = binding.as_bytes();        
    let mut key = [0u8; 32];
    key.copy_from_slice(hash_bytes);

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let nonce = aes_gcm::Nonce::from_slice(nonce);

    let private_key = cipher.decrypt(nonce, encrypted_private_key).map_err(|e| e.to_string())?;
    Ok(private_key)
}
