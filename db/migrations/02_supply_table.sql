CREATE TABLE supply (
    id SERIAL PRIMARY KEY,           -- Unique identifier for the record
    circulating_supply BIGINT NOT NULL,    -- Current total circulating supply
    max_supply BIGINT NOT NULL       -- Maximum allowable supply of coins
);
INSERT INTO supply (circulating_supply, max_supply)
VALUES (0, 2305843009213693951);
