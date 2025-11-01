use crate::{app_state::AppState, files};
use sqlx::{pool::PoolConnection, Sqlite};
use std::{io::ErrorKind, time::Duration};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::time::{interval, MissedTickBehavior};
use tracing::{debug, error, info, warn};

const CLEANUP_INTERVAL: Duration = Duration::from_secs(15 * 60);
const CLEANUP_BATCH_SIZE: i64 = 100;

/// Start the background task that periodically removes expired artifacts.
pub fn spawn_cleanup_job(state: AppState) {
    tokio::spawn(async move {
        info!(
            target: "cleanup",
            interval_secs = CLEANUP_INTERVAL.as_secs(),
            batch_size = CLEANUP_BATCH_SIZE,
            "starting cleanup background task"
        );

        let mut ticker = interval(CLEANUP_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            ticker.tick().await;

            if let Err(err) = run_cleanup_cycle(&state).await {
                error!(target: "cleanup", %err, "cleanup cycle failed");
            }
        }
    });
}

async fn run_cleanup_cycle(state: &AppState) -> Result<(), CleanupError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let mut files_removed: u64 = 0;
    let mut missing_on_disk: u64 = 0;

    loop {
        let expired = files::list_expired_files_for_cleanup(state.db(), now, CLEANUP_BATCH_SIZE)
            .await
            .map_err(CleanupError::Database)?;

        if expired.is_empty() {
            break;
        }

        for candidate in expired {
            match process_expired_file(state, &candidate, now).await {
                Ok(CleanupOutcome::Deleted {
                    file_id,
                    code,
                    missing,
                }) => {
                    files_removed += 1;
                    if missing {
                        missing_on_disk += 1;
                    }

                    info!(
                        target: "cleanup",
                        file_id = %file_id,
                        code = %code,
                        missing_on_disk = missing,
                        "expired file removed from database"
                    );
                }
                Ok(CleanupOutcome::Skipped) => {
                    debug!(
                        target: "cleanup",
                        file_id = %candidate.id,
                        code = %candidate.code,
                        "expired file skipped due to concurrent update"
                    );
                }
                Err(err) => {
                    error!(
                        target: "cleanup",
                        file_id = %candidate.id,
                        code = %candidate.code,
                        %err,
                        "failed to process expired file"
                    );
                }
            }
        }
    }

    match prune_expired_sessions(state, now).await {
        Ok(rows) if rows > 0 => {
            info!(
                target: "cleanup",
                rows,
                "pruned expired sessions"
            );
        }
        Ok(_) => {}
        Err(err) => {
            error!(target: "cleanup", %err, "failed to prune expired sessions");
        }
    }

    if files_removed > 0 {
        info!(
            target: "cleanup",
            files_removed,
            missing_on_disk,
            "expired files removed"
        );
    } else {
        debug!(target: "cleanup", "no expired files to remove in this cycle");
    }

    Ok(())
}

async fn process_expired_file(
    state: &AppState,
    candidate: &files::ExpiredFileForCleanup,
    now: i64,
) -> Result<CleanupOutcome, CleanupError> {
    let mut conn = state.db().acquire().await.map_err(CleanupError::Database)?;

    sqlx::query("BEGIN IMMEDIATE")
        .execute(conn.as_mut())
        .await
        .map_err(CleanupError::Database)?;

    let outcome = match process_expired_file_in_transaction(state, candidate, now, &mut conn).await
    {
        Ok(result) => result,
        Err(err) => {
            rollback_connection(&mut conn).await;
            return Err(err);
        }
    };

    match &outcome {
        CleanupOutcome::Deleted { .. } => {
            sqlx::query("COMMIT")
                .execute(conn.as_mut())
                .await
                .map_err(CleanupError::Database)?;
        }
        CleanupOutcome::Skipped => {
            rollback_connection(&mut conn).await;
        }
    }

    Ok(outcome)
}

async fn process_expired_file_in_transaction(
    state: &AppState,
    candidate: &files::ExpiredFileForCleanup,
    now: i64,
    conn: &mut PoolConnection<Sqlite>,
) -> Result<CleanupOutcome, CleanupError> {
    let Some(record) = files::load_expired_file_for_cleanup(conn.as_mut(), &candidate.id, now)
        .await
        .map_err(CleanupError::Database)?
    else {
        return Ok(CleanupOutcome::Skipped);
    };

    let files::ExpiredFileForCleanup {
        id,
        code,
        stored_path,
        ..
    } = record;

    let path = state.config().storage.root.join(&stored_path);

    let missing_on_disk = match tokio::fs::remove_file(&path).await {
        Ok(_) => false,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            debug!(
                target: "cleanup",
                file_id = %id,
                code = %code,
                path = %path.display(),
                "file already absent on disk during cleanup"
            );
            true
        }
        Err(err) => {
            warn!(
                target: "cleanup",
                file_id = %id,
                code = %code,
                path = %path.display(),
                %err,
                "failed to remove expired file from disk; will retry later"
            );
            return Err(CleanupError::FileRemoval {
                path: path.display().to_string(),
                source: err,
            });
        }
    };

    files::delete_file_record(conn.as_mut(), &id)
        .await
        .map_err(CleanupError::Database)?;

    Ok(CleanupOutcome::Deleted {
        file_id: id,
        code,
        missing: missing_on_disk,
    })
}

async fn prune_expired_sessions(state: &AppState, now: i64) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        DELETE FROM tower_sessions
        WHERE expiry_date IS NOT NULL
          AND expiry_date <= ?
        "#,
    )
    .bind(now)
    .execute(state.db())
    .await?;

    Ok(result.rows_affected())
}

async fn rollback_connection(conn: &mut PoolConnection<Sqlite>) {
    if let Err(err) = sqlx::query("ROLLBACK").execute(conn.as_mut()).await {
        error!(target: "cleanup", %err, "failed to rollback cleanup transaction");
    }
}

#[derive(Debug)]
enum CleanupOutcome {
    Deleted {
        file_id: String,
        code: String,
        missing: bool,
    },
    Skipped,
}

#[derive(Debug, Error)]
enum CleanupError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("failed to remove file at {path}: {source}")]
    FileRemoval {
        path: String,
        #[source]
        source: std::io::Error,
    },
}
