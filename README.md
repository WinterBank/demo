4. Prepare Dependencies
Ensure all dependencies, such as PostgreSQL and Redis, are installed and configured on your system. For example:

Install PostgreSQL
sudo apt update
sudo apt install -y postgresql

Configure db

Install Redis
sudo apt update
sudo apt install -y redis-server

Verify both are running
systemctl status postgresql
systemctl status redis

5. Set Environment Variables
Create a .env file in the directory where the binary will run. Include all necessary environment variables, e.g.:

REDIS_URL=redis://127.0.0.1:6379
API_URL=http://example.com/api
POSTGRES_URL=postgres://username:password@localhost/dbname

cd miner
cargo build --release

./target/release/miner start <account_key>


6. Run the Binary
Run the binary directly or with commands like start_mining:
./target/release/miner start_mining MyAccountName
or
./target/release/miner

7. Create a Debian Package (Optional)
To distribute the binary as a .deb package:
cargo install cargo-deb
Cargo.toml
[package.metadata.deb]
maintainer = "Your Name <your.email@example.com>"
description = "A miner for my blockchain project"
depends = "libc6, libssl-dev"

cargo deb

sudo dpkg -i target/debian/miner_0.1.0_amd64.deb

============

cargo run

create account

start mining

Miner Crate
============
Cargo.toml

[package]
name = "miner"
version = "0.1.0"
edition = "2021"

[dependencies]
argon2 = "0.5.3"
tokio = { version = "1.41.1", features = ["full"] }
rand = "0.8.5"
sqlx = { version = "0.8.2", features = ["runtime-tokio", "tls-native-tls", "postgres"] }
log = "0.4.22"
hex = "0.4.3"
num_cpus = "1.16.0"
reqwest = { version = "0.12.9", features = ["json"] }
serde = { version = "1.0.215", features = ["derive"] }
serde_json = "1.0.133"
anyhow = "1.0.94"
dotenvy = "0.15.0"
redis = "0.23.0"
env_logger = "0.10.0"

[[bin]]
name = "miner"
path = "src/main.rs"


cargo build --release


