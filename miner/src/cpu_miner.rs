// miner/src/cpu_miner.rs

use argon2::{Argon2, Params, Algorithm, Version, password_hash::SaltString};
use rand::rngs::OsRng;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::task;
use reqwest::Client as HttpClient;
use log::{info, error, debug};
use anyhow::{Result, Context};

#[derive(Clone)]
pub struct CpuMiner {
    stop_flag: Arc<AtomicBool>,
    http_client: HttpClient, // HTTP client for API submissions
    api_url: String,        // API endpoint for mining submissions
}

#[derive(serde::Deserialize)]
struct MiningParamsResponse {
    difficulty: u64,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    output_len: usize,
}

impl CpuMiner {
    /// Create a new CpuMiner
    pub fn new(api_url: String) -> Self {
        Self {
            stop_flag: Arc::new(AtomicBool::new(false)),
            http_client: HttpClient::new(),
            api_url,
        }
    }

    /// Start mining with dynamic difficulty/params
    pub fn start_mining(&self, account_key: [u8; 16]) {
        let stop_flag = self.stop_flag.clone();
        let http_client = self.http_client.clone();
        let api_url = self.api_url.clone();

        // spawn a task that fetches the official difficulty + params once and uses them
        task::spawn(async move {
            let (difficulty, params) = match Self::fetch_params_from_api_inner(&http_client, &api_url).await {
                Ok((diff, p)) => (diff, p),
                Err(e) => {
                    error!("Failed to fetch mining params from server: {}", e);
                    return;
                }
            };

            let mut nonce = 0;
            info!("Starting mining with difficulty: {}", difficulty);

            while !stop_flag.load(Ordering::Relaxed) {
                let input = format!("{:?}:{:?}", account_key, nonce);
                let salt = Self::generate_salt();
                let hash = Self::generate_argon2_hash_with_params(&input, &salt, &params);
                let url = format!("{}/submit_mining_result", api_url);

                if Self::meets_difficulty(&hash, difficulty) {
                    info!(
                        "Valid hash found: {:?} (nonce: {}, salt: {:?})",
                        hex::encode(&hash),
                        nonce,
                        hex::encode(&salt)
                    );

                    // Submit mined hash, nonce, salt, and account_key to API
                    if let Err(e) = Self::submit_to_api(&http_client, &url, account_key, nonce, &hash, &salt).await {
                        error!("Failed to submit mining result to API: {}", e);
                    }
                }

                nonce += 1;
            }
            info!("Mining stopped.");
        });
    }

    /// Stop mining
    pub fn stop_mining(&self) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }

    async fn fetch_params_from_api_inner(client: &HttpClient, api_url: &str) -> Result<(u64, Params)> {
        let url = format!("{}/mining_params", api_url);
        let resp = client.get(&url).send().await?.error_for_status()?;
        let data = resp.json::<MiningParamsResponse>().await?;
        let params = Params::new(data.m_cost, data.t_cost, data.p_cost, Some(data.output_len))
            .map_err(|e| anyhow::anyhow!("Argon2 params creation error: {}", e))?;
        Ok((data.difficulty, params))
    }

    pub fn generate_argon2_hash_with_params(input: &str, salt: &[u8], params: &Params) -> Vec<u8> {
        let argon2 = Argon2::new(Algorithm::Argon2d, Version::V0x13, params.clone());
        let mut hash = vec![0u8; 32];
        argon2
            .hash_password_into(input.as_bytes(), salt, &mut hash)
            .expect("Argon2 hashing failed");
        hash
    }
    
    pub fn generate_salt() -> Vec<u8> {
        SaltString::generate(&mut OsRng).as_str().as_bytes().to_vec()
    }    

    pub fn count_leading_zero_bits(hash: &[u8; 32]) -> u64 {
        println!("Counting leading zeros for hash: {:?}", hex::encode(hash));
        let mut count = 0;
        for byte in hash.iter() {
            if *byte == 0 {
                count += 8;
            } else {
                count += byte.leading_zeros() as u64;
                break;
            }
        }
        println!("Leading zero bits: {}", count);
        count
    }  

    /// Check if the hash meets the required difficulty
    fn meets_difficulty(hash: &[u8], difficulty: u64) -> bool {
        let leading_zero_bits = Self::count_leading_zero_bits(&hash.try_into().expect("Hash should be 32 bytes"));
    
        leading_zero_bits >= difficulty
    }      

    /// Submit mining result to API
    async fn submit_to_api(
        client: &HttpClient,
        api_url: &str,
        account_key: [u8; 16],
        nonce: u64,
        hash: &[u8],
        salt: &[u8],
    ) -> Result<()> {
        info!(
            "Submitting mining result: account_key={:?}, nonce={}, hash={:?}, salt={:?}",
            account_key,
            nonce,
            hash,
            salt
        );
    
        let response = client
            .post(api_url)
            .json(&serde_json::json!({
                "account_key": account_key,
                "nonce": nonce,
                "hash": hash,
                "salt": salt,
            }))
            .send()
            .await
            .context("Failed to send request to API")?;
    
        if response.status().is_success() {
            info!("Mining result submitted successfully.");
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_else(|_| "unknown error".to_string());
            error!("Failed to submit mining result: HTTP {} - {}", status, body);
            Err(anyhow::anyhow!("HTTP Error: {} - {}", status, body))
        }
    }    
}