CREATE TABLE transactions (
    id BYTEA PRIMARY KEY,
    sender_key BYTEA NOT NULL,
    receiver_key BYTEA NOT NULL,
    amount BIGINT NOT NULL,
    signature BYTEA NOT NULL,
    leaf_index INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_transactions_sender_key ON transactions(sender_key);
CREATE INDEX idx_transactions_receiver_key ON transactions(receiver_key);
