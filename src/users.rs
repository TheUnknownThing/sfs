use crate::auth::UserRecord;
use sqlx::SqlitePool;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserSummary {
    pub id: i64,
    pub username: String,
    pub is_admin: bool,
    pub created_at: i64,
    pub last_login_at: Option<i64>,
}

/// Fetch the list of all users ordered by username.
pub async fn list_users(pool: &SqlitePool) -> Result<Vec<UserSummary>, sqlx::Error> {
    let rows = sqlx::query_as!(
        UserSummary,
        r#"
        SELECT
            id,
            username,
            is_admin as "is_admin: bool",
            created_at,
            last_login_at
        FROM users
        ORDER BY username COLLATE NOCASE
        "#
    )
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Insert a new user record.
pub async fn create_user(
    pool: &SqlitePool,
    username: &str,
    password_hash: &str,
    is_admin: bool,
) -> Result<(), sqlx::Error> {
    let admin_flag = if is_admin { 1 } else { 0 };

    sqlx::query!(
        r#"
        INSERT INTO users (username, password_hash, is_admin, created_at, last_login_at)
        VALUES (?, ?, ?, strftime('%s', 'now'), NULL)
        "#,
        username,
        password_hash,
        admin_flag
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete a user by identifier. Returns the number of affected rows.
pub async fn delete_user(pool: &SqlitePool, user_id: i64) -> Result<u64, sqlx::Error> {
    let result = sqlx::query!("DELETE FROM users WHERE id = ?", user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

/// Count the number of administrator accounts.
pub async fn count_admin_users(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
    let count = sqlx::query_scalar!("SELECT COUNT(*) FROM users WHERE is_admin = 1")
        .fetch_one(pool)
        .await?;

    Ok(i64::from(count))
}

/// Lookup a user record by identifier.
pub async fn find_user_by_id(
    pool: &SqlitePool,
    user_id: i64,
) -> Result<Option<UserRecord>, sqlx::Error> {
    let record = sqlx::query_as!(
        UserRecord,
        r#"
        SELECT id, username, password_hash, is_admin as "is_admin: bool"
        FROM users
        WHERE id = ?
        "#,
        user_id
    )
    .fetch_optional(pool)
    .await?;

    Ok(record)
}
