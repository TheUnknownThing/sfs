use axum::routing::{get, post};
use axum::Router;
use tower::ServiceBuilder;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;
use tower_sessions::SessionManagerLayer;
use tower_sessions_sqlx_store::SqliteStore;

use crate::app_state::AppState;
use crate::server::constants::MULTIPART_OVERHEAD_BYTES;
use crate::server::handlers;

/// Construct the application's HTTP router with all routes and middleware configured.
pub fn build_router(state: AppState, session_layer: SessionManagerLayer<SqliteStore>) -> Router {
    let upload_body_limit = state
        .config()
        .storage
        .max_file_size_bytes
        .saturating_add(MULTIPART_OVERHEAD_BYTES);

    let upload_routes = Router::new()
        .route(
            "/upload",
            get(handlers::uploads::upload_form_handler)
                .post(handlers::uploads::upload_submit_handler),
        )
        .layer(RequestBodyLimitLayer::new(upload_body_limit as usize));

    Router::new()
        .route("/", get(handlers::home::home_handler))
        .route("/f/:code", get(handlers::files::file_lookup_handler))
        .route(
            "/f/:code/link",
            post(handlers::files::file_direct_link_handler),
        )
        .route(
            "/f/:code/delete",
            post(handlers::files::file_delete_handler),
        )
        .route("/d/:token", get(handlers::downloads::download_handler))
        .route(
            "/login",
            get(handlers::auth::login_form_handler).post(handlers::auth::login_submit_handler),
        )
        .route(
            "/register",
            get(handlers::auth::register_form_handler)
                .post(handlers::auth::register_submit_handler),
        )
        .route("/logout", post(handlers::auth::logout_handler))
        .route(
            "/settings",
            get(handlers::settings::settings_form_handler)
                .post(handlers::settings::settings_submit_handler),
        )
        .route(
            "/admin/users",
            get(handlers::admin::user_management_page_handler)
                .post(handlers::admin::user_create_handler),
        )
        .route(
            "/admin/users/:id/reset-password",
            post(handlers::admin::user_reset_password_handler),
        )
        .route(
            "/admin/users/:id/delete",
            post(handlers::admin::user_delete_handler),
        )
        .route(
            "/paste",
            get(handlers::paste::paste_form_handler).post(handlers::paste::paste_submit_handler),
        )
        .merge(upload_routes)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(session_layer),
        )
        .with_state(state)
}
