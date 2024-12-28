CREATE TABLE rewards (
    id SERIAL PRIMARY KEY,
    public_key BYTEA NOT NULL REFERENCES accounts(public_key),
    amount BIGINT NOT NULL,
    reward_hash BYTEA NOT NULL CHECK (octet_length(reward_hash) = 32),
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_rewards_public_key ON rewards(public_key);
