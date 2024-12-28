CREATE TABLE global_state_roots (
    id SERIAL PRIMARY KEY,
    root BYTEA NOT NULL CHECK (octet_length(root) = 32),
    created_at TIMESTAMP DEFAULT NOW()
);
