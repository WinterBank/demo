// miner/src/main.rs

use std::sync::Arc;
use tokio::signal;
use miner::cpu_miner::CpuMiner;
use std::env;
use hex::FromHex;
use tokio::time::{self, Duration};
use anyhow::Error;

const ACTIX_HTTP_URL: &str = "http://demo.peerlync.com:8080";

#[tokio::main]
async fn main() {
    println!("Starting miner...");

    // Initialize the CPU miner
    let cpu_miner = Arc::new(CpuMiner::new(ACTIX_HTTP_URL.to_string()));

    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        match args[1].as_str() {
            "start" => {
                if args.len() != 3 {
                    eprintln!("Usage: miner start <account_key>");
                    std::process::exit(1);
                }

                let account_key = args[2].clone();
                let account_key_bytes: [u8; 16] = match <[u8; 16]>::from_hex(&account_key) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        eprintln!("Invalid account key. Ensure it is a valid 32-character hex string.");
                        std::process::exit(1);
                    }
                };

                println!("Starting mining for account key: {:?}", account_key_bytes);

                let miner = cpu_miner.clone(); // Clone the Arc to share ownership
                let stop_flag = cpu_miner.clone(); // Another clone for stopping mining

                let handle = tokio::spawn(async move {
                    miner.start_mining(account_key_bytes);
                });

                // Wait for Ctrl+C signal to stop mining
                signal::ctrl_c().await.expect("Failed to listen for Ctrl+C signal");

                // Stop mining
                stop_flag.stop_mining();

                // Await the spawned task to ensure it finishes cleanly
                handle.await.expect("Failed to stop mining gracefully");

                println!("Mining stopped.");
            }
            "stop" => {
                cpu_miner.stop_mining();
                println!("Mining stopped.");
            }
            _ => {
                eprintln!("Unknown command. Available commands: start, stop");
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("Usage: miner <start|stop> [account_key]");
        std::process::exit(1);
    }
}
