use std::sync::Arc;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use tower_sessions::Session;
use tracing::error;

use crate::{
    app_state::AppState,
    sessions::{current_user, SessionUser},
    settings::AppSettings,
    templates::LayoutContext,
};

use crate::server::utils::server_error_response;

/// Build a [`LayoutContext`] from the current session, falling back to a state-only context when
/// the session lookup fails.
pub async fn layout_from_session(
    state: &AppState,
    session: &Session,
    title: &str,
) -> LayoutContext {
    match LayoutContext::from_session(state, session, title).await {
        Ok(layout) => layout,
        Err(err) => {
            error!(target: "templates", %err, "failed to build layout context from session");
            LayoutContext::from_state(state, title).await
        }
    }
}

/// Resolve the cached application settings, returning a shared reference or an error response.
pub async fn current_app_settings(state: &AppState) -> Result<Arc<AppSettings>, Response> {
    match state.settings().current().await {
        Ok(settings) => Ok(settings),
        Err(err) => {
            error!(
                target: "settings",
                %err,
                "failed to load application settings from database"
            );
            Err(server_error_response())
        }
    }
}

/// Ensure the current session belongs to an administrator.
pub async fn require_admin(session: &Session) -> Result<SessionUser, Response> {
    match current_user(session).await {
        Ok(Some(user)) if user.is_admin => Ok(user),
        Ok(Some(user)) => {
            tracing::warn!(
                target: "settings",
                user_id = user.id,
                username = %user.username,
                "non-admin attempted to access restricted area"
            );
            Err((
                StatusCode::FORBIDDEN,
                "You are not authorized to manage settings.",
            )
                .into_response())
        }
        Ok(None) => Err(Redirect::to("/login").into_response()),
        Err(err) => {
            error!(
                target: "sessions",
                %err,
                "failed to read session while enforcing admin access"
            );
            Err(server_error_response())
        }
    }
}
