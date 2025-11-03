use std::borrow::ToOwned;
use std::time::Duration;

use argon2::{
    password_hash::{
        rand_core::OsRng, Error as PasswordHashError, PasswordHash, PasswordHasher,
        PasswordVerifier, SaltString,
    },
    Algorithm, Argon2, Params, Version,
};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use thiserror::Error;
use tokio::task;
use tracing::info;

use crate::config::AppConfig;

/// Minimum allowed length for usernames.
const USERNAME_MIN_LEN: usize = 3;
/// Maximum allowed length for usernames.
const USERNAME_MAX_LEN: usize = 64;
/// Minimum required length for passwords.
const PASSWORD_MIN_LEN: usize = 12;
/// Argon2 memory cost in kibibytes (~19 MB).
const ARGON2_MEMORY_COST: u32 = 19_456;
/// Argon2 time cost (iterations).
const ARGON2_TIME_COST: u32 = 2;
/// Argon2 parallelism (lanes).
const ARGON2_PARALLELISM: u32 = 1;
/// Length of the produced password hash output (bytes).
const ARGON2_OUTPUT_LENGTH: usize = 32;

/// Represents a user record retrieved from the database.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserRecord {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    #[sqlx(rename = "is_admin")]
    pub is_admin: bool,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid username")]
    InvalidUsername,
    #[error("Invalid password")]
    InvalidPassword,
    #[error("Authentication failed")]
    InvalidCredentials,
    #[error("Password hashing join error: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("Password hashing error: {0:?}")]
    PasswordHash(PasswordHashError),
    #[error("Argon2 error: {0:?}")]
    Argon2(argon2::Error),
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Bootstrap credentials are invalid: {0}")]
    BootstrapValidation(&'static str),
}

/// Combine the optional pepper with the provided password.
fn combine_password_and_pepper(password: &str, pepper: Option<&str>) -> String {
    match pepper {
        Some(pepper) => {
            let mut combined = String::with_capacity(pepper.len() + password.len());
            combined.push_str(pepper);
            combined.push_str(password);
            combined
        }
        None => password.to_owned(),
    }
}

/// Create an Argon2 instance with the desired security parameters.
fn configured_argon2() -> Result<Argon2<'static>, AuthError> {
    let params = Params::new(
        ARGON2_MEMORY_COST,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(ARGON2_OUTPUT_LENGTH),
    )
    .map_err(AuthError::Argon2)?;

    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Hash a password using Argon2id with strong parameters.
pub async fn hash_password(password: &str, pepper: Option<&str>) -> Result<String, AuthError> {
    let password = password.to_owned();
    let pepper = pepper.map(ToOwned::to_owned);

    Ok(task::spawn_blocking(move || {
        let password_material = combine_password_and_pepper(&password, pepper.as_deref());
        let argon2 = configured_argon2()?;
        let salt = SaltString::generate(&mut OsRng);
        let hash = argon2
            .hash_password(password_material.as_bytes(), &salt)
            .map_err(AuthError::PasswordHash)?
            .to_string();
        Ok::<_, AuthError>(hash)
    })
    .await??)
}

/// Verify a password against a stored hash and signal whether a rehash is required.
pub async fn verify_password(
    password: &str,
    stored_hash: &str,
    pepper: Option<&str>,
) -> Result<PasswordVerification, AuthError> {
    let password = password.to_owned();
    let stored_hash = stored_hash.to_owned();
    let pepper = pepper.map(ToOwned::to_owned);

    Ok(task::spawn_blocking(move || {
        let parsed_hash = PasswordHash::new(&stored_hash).map_err(AuthError::PasswordHash)?;
        let password_material = combine_password_and_pepper(&password, pepper.as_deref());
        let verifier = configured_argon2()?;

        match verifier.verify_password(password_material.as_bytes(), &parsed_hash) {
            Ok(_) => {
                let needs_rehash = password_needs_rehash(&parsed_hash)?;
                Ok::<_, AuthError>(PasswordVerification { needs_rehash })
            }
            Err(err) => {
                if matches!(err, PasswordHashError::Password) {
                    Err(AuthError::InvalidCredentials)
                } else {
                    Err(AuthError::PasswordHash(err))
                }
            }
        }
    })
    .await??)
}

fn password_needs_rehash(hash: &PasswordHash<'_>) -> Result<bool, AuthError> {
    let params = Params::try_from(hash).map_err(AuthError::PasswordHash)?;
    let version_mismatch = hash.version != Some(Version::V0x13 as u32);
    let algorithm_mismatch = hash.algorithm.as_str() != "argon2id";
    let output_length = hash.hash.map(|digest| digest.len()).unwrap_or_default();

    let needs_rehash = params.m_cost() < ARGON2_MEMORY_COST
        || params.t_cost() < ARGON2_TIME_COST
        || params.p_cost() < ARGON2_PARALLELISM
        || version_mismatch
        || algorithm_mismatch
        || output_length < ARGON2_OUTPUT_LENGTH;
    Ok(needs_rehash)
}

/// Validate username constraints and return the normalized username (lowercase, trimmed).
pub fn normalize_username(input: &str) -> Result<String, AuthError> {
    let trimmed = input.trim();
    if trimmed.len() < USERNAME_MIN_LEN || trimmed.len() > USERNAME_MAX_LEN {
        return Err(AuthError::InvalidUsername);
    }

    if trimmed.chars().any(|c| c.is_whitespace()) {
        return Err(AuthError::InvalidUsername);
    }

    Ok(trimmed.to_lowercase())
}

/// Validate password constraints.
pub fn validate_password_strength(password: &str) -> Result<(), AuthError> {
    if password.len() < PASSWORD_MIN_LEN {
        return Err(AuthError::InvalidPassword);
    }
    Ok(())
}

/// Update a user's password hash.
pub async fn update_password_hash(
    pool: &SqlitePool,
    user_id: i64,
    new_hash: &str,
) -> Result<(), AuthError> {
    sqlx::query!(
        r#"
        UPDATE users
        SET password_hash = ?, last_login_at = strftime('%s', 'now')
        WHERE id = ?
        "#,
        new_hash,
        user_id
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Record that a user successfully logged in without requiring a password rehash.
pub async fn touch_user_login(pool: &SqlitePool, user_id: i64) -> Result<(), AuthError> {
    sqlx::query!(
        r#"
        UPDATE users
        SET last_login_at = strftime('%s', 'now')
        WHERE id = ?
        "#,
        user_id
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Bootstrap the initial administrator account if the database is empty.
pub async fn bootstrap_admin_user(pool: &SqlitePool, config: &AppConfig) -> Result<(), AuthError> {
    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?;

    if user_count > 0 {
        return Ok(());
    }

    let env_username = std::env::var("BOOTSTRAP_ADMIN_USERNAME").ok();
    let env_password = std::env::var("BOOTSTRAP_ADMIN_PASSWORD").ok();

    let (username, password) = match (env_username, env_password) {
        (Some(username), Some(password)) => (username, password),
        _ => {
            info!("No bootstrap credentials provided; administrator account not created");
            return Ok(());
        }
    };

    if username.trim().is_empty() {
        return Err(AuthError::BootstrapValidation("username cannot be empty"));
    }

    if password.is_empty() {
        return Err(AuthError::BootstrapValidation("password cannot be empty"));
    }

    let normalized_username = normalize_username(&username)
        .map_err(|_| AuthError::BootstrapValidation("username failed validation"))?;
    validate_password_strength(&password)
        .map_err(|_| AuthError::BootstrapValidation("password does not meet complexity"))?;

    let password_hash =
        hash_password(&password, config.security.password_pepper.as_deref()).await?;

    sqlx::query!(
        r#"
        INSERT INTO users (username, password_hash, is_admin, created_at, last_login_at)
        VALUES (?, ?, 1, strftime('%s', 'now'), NULL)
        "#,
        normalized_username,
        password_hash
    )
    .execute(pool)
    .await?;

    info!(username = %normalized_username, "Bootstrap administrator account created");

    Ok(())
}

/// The outcome of password verification.
#[derive(Debug, Clone, Copy)]
pub struct PasswordVerification {
    pub needs_rehash: bool,
}

/// Introduce a small random backoff when login fails to slow brute-force attempts.
pub async fn randomized_backoff() {
    let base_delay = Duration::from_millis(150);
    let jitter = Duration::from_millis(fastrand::u64(0..150));
    tokio::time::sleep(base_delay + jitter).await;
}

/// Helper to fetch a user record by username.
pub async fn find_user_by_username(
    pool: &SqlitePool,
    username: &str,
) -> Result<Option<UserRecord>, AuthError> {
    let record = sqlx::query_as::<_, UserRecord>(
        r#"
        SELECT id, username, password_hash, is_admin
        FROM users
        WHERE username = ?
        "#,
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;

    Ok(record)
}
