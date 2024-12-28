// wallet_core/src/encryption.rs

use argon2::{
    password_hash::{SaltString, PasswordHasher, PasswordVerifier, rand_core::OsRng},
    Argon2, Params, PasswordHash,
};
use anyhow::{anyhow, Result};

/// Encrypt the private key using password-based Argon2 + XChaCha20-Poly1305 (as an example).
/// In your server code, you are using `models::utils::encrypt_private_key`; replicate that here
/// so that the client can do the exact same encryption without sending the password to the server.
pub fn encrypt_private_key(
    password: &str,
    private_key: &[u8],
) -> (Vec<u8>, Vec<u8>, Vec<u8>, u32) {
    // Example Argon2 params. Adjust as necessary to match server.
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    // Derive a 32-byte key from the password
    let key = argon2_hash_key(password, salt.as_str().as_bytes(), 32, 2).unwrap();

    // Now do XChaCha20-Poly1305 or your chosen AEAD
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};

    let cipher = XChaCha20Poly1305::new((&*key).into());
    let nonce_bytes = {
        let mut b = [0u8; 24];
        getrandom::getrandom(&mut b).expect("Failed to generate nonce");
        b
    };
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, private_key)
        .expect("encryption failure!");

    // We'll store the Argon2 iteration count or m_cost, etc. as well
    let kdf_iterations = 2u32; // Example

    (
        ciphertext,
        nonce_bytes.to_vec(),
        salt.as_str().as_bytes().to_vec(),
        kdf_iterations,
    )
}

/// Decrypt the private key using password-based Argon2 + XChaCha20-Poly1305.
/// Must match the same approach used in `encrypt_private_key`.
pub fn decrypt_private_key(
    password: &str,
    encrypted_private_key: &[u8],
    nonce: &[u8],
    salt: &[u8],
    kdf_iterations: u32,
) -> Result<Vec<u8>> {
    let key = argon2_hash_key(password, salt, 32, kdf_iterations)?;

    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};

    let cipher = XChaCha20Poly1305::new((&*key).into());
    let xnonce = XNonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(xnonce, encrypted_private_key)
        .map_err(|e| anyhow!("Failed to decrypt private key: {:?}", e))?;

    Ok(plaintext)
}

/// Hash the password to produce a 32-byte key using Argon2 with custom `t_cost`.
fn argon2_hash_key(
    password: &str,
    salt: &[u8],
    desired_key_len: usize,
    t_cost: u32,
) -> Result<Vec<u8>> {
    let params = Params::new(32 * 1024, t_cost, 1, Some(desired_key_len))
        .map_err(|e| anyhow!("Argon2 params error: {:?}", e))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut output_key = vec![0u8; desired_key_len];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output_key)
        .map_err(|e| anyhow!("Argon2 hashing failed: {:?}", e))?;

    Ok(output_key)
}

/// Generate a 16-byte "account key" from the 32-byte public key
/// (similar to your server code).
pub fn generate_account_key(public_key: &[u8]) -> [u8; 16] {
    let hash = blake3::hash(public_key);
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&hash.as_bytes()[..16]);
    arr
}
