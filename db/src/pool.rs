// db/src/pool.rs

use sqlx::{Pool, Postgres};
use std::env;

pub type DbPool = Pool<Postgres>;

pub async fn create_pool() -> DbPool {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    Pool::<Postgres>::connect(&database_url)
        .await
        .expect("Failed to create pool")
}
