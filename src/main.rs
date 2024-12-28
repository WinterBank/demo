// src/main.rs

use dotenvy::dotenv;
use db::pool::create_pool;
use api::server::start_server;
use api::utils::*;
use miner::cpu_miner::CpuMiner;
use redis::{Client as RedisClient};
use std::env;
use std::sync::Arc;
use tokio::signal;
use env_logger;

#[tokio::main]
async fn main() {
    // Load environment variables and initialize logger
    dotenv().ok();
    env_logger::init();

    println!("Starting application...");

    // Create a database connection pool
    let pool = create_pool().await;

    // Initialize the Redis client
    println!("Initializing Redis client");
    let redis_url = env::var("REDIS_URL").expect("REDIS_URL must be set in .env");
    let redis_client = RedisClient::open(redis_url).expect("Failed to create Redis client");

    if !test_redis_connection(&redis_client).await {
        eprintln!("Redis connection failed. Exiting...");
        std::process::exit(1);
    }

    // Initialize the CPU miner
    let api_url = env::var("API_URL").expect("API_URL must be set in .env");
    let cpu_miner = Arc::new(CpuMiner::new(api_url.clone()));

    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        match args[1].as_str() {
            "start_mining" => {
                if args.len() != 3 {
                    eprintln!("Usage: start_mining <name>");
                    std::process::exit(1);
                }

                let name = args[2].clone();

                // Retrieve the account_key for the given name
                let account_key = match get_account_key(&pool, &name).await {
                    Ok(key) => key,
                    Err(err) => {
                        eprintln!("Error retrieving account key: {}", err);
                        std::process::exit(1);
                    }
                };

                // Start mining
                println!("Starting mining for account '{}'. Press Ctrl+C to stop.", name);
                let miner = cpu_miner.clone(); // Clone the Arc to keep one for this scope
                let handle = tokio::spawn({
                    let miner = miner.clone(); // Clone again for the async move block
                    async move {
                        miner.start_mining(account_key);
                    }
                });
                
                // Wait for Ctrl+C to stop mining
                signal::ctrl_c().await.expect("Failed to listen for Ctrl+C signal");
                
                // Stop mining using the original `miner` instance in this scope
                miner.stop_mining();
                
                // Await the spawned task
                handle.await.expect("Failed to stop mining gracefully");
                println!("Mining stopped.");                
            }
            "stop_mining" => {
                cpu_miner.stop_mining();
                println!("Mining stopped.");
            }
            _ => {
                eprintln!("Unknown command. Available commands: start_mining, stop_mining");
                std::process::exit(1);
            }
        }
    } else {
        // Start the HTTP server if no CLI command is provided
        println!("Starting servers...");
        start_server(pool, cpu_miner, redis_client).await;
    }
}
