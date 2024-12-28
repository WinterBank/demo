CREATE TABLE accounts (
    public_key BYTEA PRIMARY KEY CHECK (octet_length(public_key) = 32), -- Ed25519 public key (32 bytes)
    name TEXT UNIQUE NOT NULL,
    encrypted_private_key BYTEA NOT NULL,             -- Ed25519 private key encrypted with Argon2 (Vec<u8>)
    private_key_nonce BYTEA NOT NULL,       -- Nonce for AES-GCM
    kdf_salt BYTEA NOT NULL,                -- Salt for Argon2 
    kdf_iterations INTEGER NOT NULL,        -- Argon2 iterations
    created_at TIMESTAMP DEFAULT NOW()      -- Account creation time
);
CREATE INDEX idx_accounts_name ON accounts(name);
