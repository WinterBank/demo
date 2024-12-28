CREATE TABLE account_keys (
    public_key BYTEA NOT NULL REFERENCES accounts(public_key),
    sub_name TEXT NOT NULL,
    account_key BYTEA NOT NULL CHECK (octet_length(account_key) = 16),
    balance BIGINT NOT NULL DEFAULT 0 CHECK (balance >= 0), -- Ensures non-negative balances
    account_hash BYTEA NOT NULL DEFAULT '\\x',
    created_at TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (public_key, sub_name),
    UNIQUE (account_key)
);
CREATE INDEX idx_account_key ON account_keys(account_key);
