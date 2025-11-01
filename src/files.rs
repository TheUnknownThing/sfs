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
