use sqlx::SqlitePool;

/// Represents a new file ready to be persisted to the database.
pub struct NewFileRecord<'a> {
    pub id: &'a str,
    pub owner_user_id: Option<i64>,
    pub code: &'a str,
    pub original_name: &'a str,
    pub stored_path: &'a str,
    pub size_bytes: i64,
    pub content_type: Option<&'a str>,
    pub checksum: Option<&'a str>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
}

/// Metadata exposed when looking up a file by its public code.
#[allow(dead_code)]
#[derive(Debug, sqlx::FromRow)]
pub struct FileLookup {
    pub id: String,
    pub owner_user_id: Option<i64>,
    pub code: String,
    pub original_name: String,
    pub stored_path: String,
    pub size_bytes: i64,
    pub content_type: Option<String>,
    pub checksum: Option<String>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
}

/// Lightweight summary of a user's upload for dashboard listings.
#[derive(Debug, sqlx::FromRow)]
pub struct UserFileSummary {
    pub code: String,
    pub original_name: String,
    pub size_bytes: i64,
    pub created_at: i64,
}

/// Insert a freshly uploaded file into the database.
pub async fn insert_file_record(
    pool: &SqlitePool,
    record: &NewFileRecord<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO files (
            id,
            owner_user_id,
            code,
            original_name,
            stored_path,
            size_bytes,
            content_type,
            checksum,
            created_at,
            expires_at,
            last_accessed_at
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL
        )
        "#,
    )
    .bind(record.id)
    .bind(record.owner_user_id)
    .bind(record.code)
    .bind(record.original_name)
    .bind(record.stored_path)
    .bind(record.size_bytes)
    .bind(record.content_type)
    .bind(record.checksum)
    .bind(record.created_at)
    .bind(record.expires_at)
    .execute(pool)
    .await?;

    Ok(())
}

/// Return the most recent uploads for a specific user.
pub async fn list_recent_files_for_user(
    pool: &SqlitePool,
    user_id: i64,
    limit: i64,
) -> Result<Vec<UserFileSummary>, sqlx::Error> {
    sqlx::query_as::<_, UserFileSummary>(
        r#"
        SELECT code, original_name, size_bytes, created_at
        FROM files
        WHERE owner_user_id = ?
        ORDER BY created_at DESC
        LIMIT ?
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Lookup a file by its public sharing code.
pub async fn find_file_by_code(
    pool: &SqlitePool,
    code: &str,
) -> Result<Option<FileLookup>, sqlx::Error> {
    sqlx::query_as::<_, FileLookup>(
        r#"
        SELECT
            id,
            owner_user_id,
            code,
            original_name,
            stored_path,
            size_bytes,
            content_type,
            checksum,
            created_at,
            expires_at
        FROM files
        WHERE code = ?
        LIMIT 1
        "#,
    )
    .bind(code)
    .fetch_optional(pool)
    .await
}

/// Lookup a file by its internal identifier.
pub async fn find_file_by_id(
    pool: &SqlitePool,
    file_id: &str,
) -> Result<Option<FileLookup>, sqlx::Error> {
    sqlx::query_as::<_, FileLookup>(
        r#"
        SELECT
            id,
            owner_user_id,
            code,
            original_name,
            stored_path,
            size_bytes,
            content_type,
            checksum,
            created_at,
            expires_at
        FROM files
        WHERE id = ?
        LIMIT 1
        "#,
    )
    .bind(file_id)
    .fetch_optional(pool)
    .await
}

/// Update the last accessed timestamp for a file.
pub async fn update_last_accessed(
    pool: &SqlitePool,
    file_id: &str,
    accessed_at: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE files
        SET last_accessed_at = ?
        WHERE id = ?
        "#,
    )
    .bind(accessed_at)
    .bind(file_id)
    .execute(pool)
    .await?;

    Ok(())
}
