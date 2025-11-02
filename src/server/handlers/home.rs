use axum::{extract::Query, response::IntoResponse};
use serde::Deserialize;
use tower_sessions::Session;
use tracing::{debug, error};

use crate::{
    app_state::AppState,
    files,
    sessions::current_user,
    templates::{HomeTemplate, HomeUploadRow, HtmlTemplate},
};

use super::shared::layout_from_session;
use crate::server::{
    constants::DEFAULT_RECENT_UPLOADS_LIMIT,
    utils::{format_datetime_utc, human_readable_size},
};

#[derive(Debug, Default, Deserialize)]
pub struct HomeQueryParams {
    #[serde(default)]
    pub flash: Option<String>,
}

/// Render the application home page, including recent uploads for authenticated users.
pub async fn home_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: Session,
    Query(query): Query<HomeQueryParams>,
) -> impl IntoResponse {
    let flash_message = match query.flash.as_deref() {
        Some("deleted") => Some("File deleted successfully.".to_string()),
        _ => None,
    };

    let session_user = match current_user(&session).await {
        Ok(user) => user,
        Err(err) => {
            error!(target: "sessions", %err, "failed to read session while rendering home");
            None
        }
    };

    let layout = layout_from_session(&state, &session, "Home").await;
    let mut template = HomeTemplate::new(layout);

    if let Some(user) = session_user {
        match files::list_recent_files_for_user(state.db(), user.id, DEFAULT_RECENT_UPLOADS_LIMIT)
            .await
        {
            Ok(records) => {
                let uploads = records
                    .into_iter()
                    .filter_map(map_user_file_summary_for_home)
                    .collect();
                template = template.with_recent_uploads(uploads);
            }
            Err(err) => {
                error!(target: "files", user_id = user.id, %err, "failed to load recent uploads");
            }
        }
    }

    template = template.with_flash_message(flash_message);

    HtmlTemplate::new(template)
}

fn map_user_file_summary_for_home(record: files::UserFileSummary) -> Option<HomeUploadRow> {
    if record.size_bytes < 0 {
        debug!(
            target: "files",
            size = record.size_bytes,
            code = record.code,
            "ignoring file with negative size"
        );
        return None;
    }

    let size_display = human_readable_size(record.size_bytes as u64);
    let created_display = match time::OffsetDateTime::from_unix_timestamp(record.created_at) {
        Ok(dt) => format_datetime_utc(dt),
        Err(err) => {
            debug!(
                target: "files",
                %err,
                created_at = record.created_at,
                code = record.code,
                "invalid created_at stored for file"
            );
            return None;
        }
    };

    Some(HomeUploadRow {
        code: record.code,
        original_name: record.original_name,
        size_display,
        created_display,
    })
}
