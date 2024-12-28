// api/src/mining_params.rs

use argon2::Params;

/// The global mining difficulty,
/// enforced by WinterBank when verifying mining submissions.
pub const DIFFICULTY: u64 = 10;

/// The Argon2 parameters used for hashing.
/// This is the canonical "official" set of parameters
/// that all miners must use if they want valid hashes.
pub fn mining_params() -> Params {
    // Tune these as needed
    Params::new(
        32 * 1024,  // m_cost: memory usage in KiB Example: (32,768 = 32 MB).
        1,          // t_cost: number of iterations
        1,          // p_cost: number of parallelism (lanes)
        Some(32),   // output length in bytes
    )
    .expect("Failed to create Argon2 parameters")
}
