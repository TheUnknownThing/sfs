use axum::{
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Form,
};
use serde::Deserialize;
use tower_sessions::Session;
use tracing::{debug, error, info, warn};

use crate::{
    app_state::AppState,
    auth::{
        find_user_by_username, hash_password, normalize_username, update_password_hash,
        validate_password_strength, AuthError,
    },
    csrf,
    templates::{
        AddUserFieldErrors, AddUserFormValues, HtmlTemplate, ManagedUserRow, UserManagementTemplate,
    },
    users,
};

use crate::server::utils::{format_datetime_utc, is_unique_violation, server_error_response};

use super::shared::{layout_from_session, require_admin};

#[derive(Debug, Deserialize)]
pub(crate) struct AddUserFormSubmission {
    csrf_token: String,
    username: String,
    password: String,
    password_confirm: String,
    is_admin: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ResetUserPasswordForm {
    csrf_token: String,
    new_password: String,
    confirm_password: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DeleteUserForm {
    csrf_token: String,
}

pub async fn user_management_page_handler(
    State(state): State<AppState>,
    session: Session,
) -> Response {
    if let Err(response) = require_admin(&session).await.map(|_| ()) {
        return response;
    }

    let users = match fetch_user_rows(&state).await {
        Ok(rows) => rows,
        Err(response) => return response,
    };

    render_user_management_page(
        &state,
        &session,
        StatusCode::OK,
        users,
        AddUserFormValues::default(),
        AddUserFieldErrors::default(),
        None,
        None,
    )
    .await
}

pub async fn user_create_handler(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<AddUserFormSubmission>,
) -> Response {
    let admin = match require_admin(&session).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let csrf_valid = match csrf::validate_csrf_token(&session, &form.csrf_token).await {
        Ok(valid) => valid,
        Err(err) => {
            error!(target: "csrf", %err, "failed to validate CSRF token for add-user");
            return server_error_response();
        }
    };

    if !csrf_valid {
        warn!(target: "csrf", user_id = admin.id, "add-user request failed CSRF validation");
        if let Err(err) = csrf::rotate_csrf_token(&session).await {
            error!(target: "csrf", %err, "failed to rotate CSRF token after add-user failure");
        }
        return match fetch_user_rows(&state).await {
            Ok(users) => {
                render_user_management_page(
                    &state,
                    &session,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    users,
                    AddUserFormValues {
                        username: form.username.trim().to_string(),
                        is_admin: form.is_admin.is_some(),
                    },
                    AddUserFieldErrors::default(),
                    Some("Your session expired. Please try again.".to_string()),
                    None,
                )
                .await
            }
            Err(response) => response,
        };
    }

    let mut field_errors = AddUserFieldErrors::default();
    let mut has_errors = false;
    let username_input = form.username.trim();
    let add_form = AddUserFormValues {
        username: username_input.to_string(),
        is_admin: form.is_admin.is_some(),
    };

    let normalized_username = match normalize_username(username_input) {
        Ok(username) => username,
        Err(_) => {
            field_errors.username =
                Some("Enter a username between 3 and 64 characters without spaces.".to_string());
            has_errors = true;
            String::new()
        }
    };

    if let Err(err) = validate_password_strength(&form.password) {
        match err {
            AuthError::InvalidPassword => {
                field_errors.password =
                    Some("Password must be at least 12 characters long.".to_string());
            }
            _ => {
                error!(target: "auth", %err, "unexpected password validation error while adding user");
                return server_error_response();
            }
        }
        has_errors = true;
    }

    if form.password != form.password_confirm {
        field_errors.password_confirm = Some("Passwords do not match.".to_string());
        has_errors = true;
    }

    if normalized_username.is_empty() {
        has_errors = true;
    }

    let users_snapshot = match fetch_user_rows(&state).await {
        Ok(rows) => rows,
        Err(response) => return response,
    };

    if has_errors {
        return render_user_management_page(
            &state,
            &session,
            StatusCode::UNPROCESSABLE_ENTITY,
            users_snapshot,
            add_form,
            field_errors,
            Some("Please correct the highlighted fields.".to_string()),
            None,
        )
        .await;
    }

    match find_user_by_username(state.db(), &normalized_username).await {
        Ok(Some(_)) => {
            field_errors.username = Some("That username is already taken.".to_string());
            return render_user_management_page(
                &state,
                &session,
                StatusCode::UNPROCESSABLE_ENTITY,
                users_snapshot,
                add_form,
                field_errors,
                Some("Unable to create the user.".to_string()),
                None,
            )
            .await;
        }
        Ok(None) => {}
        Err(err) => {
            error!(target: "auth", %err, "failed to check existing user during add-user");
            return server_error_response();
        }
    }

    let password_hash = match hash_password(
        &form.password,
        state.config().security.password_pepper.as_deref(),
    )
    .await
    {
        Ok(hash) => hash,
        Err(err) => {
            error!(target: "auth", %err, "failed to hash password while adding user");
            return server_error_response();
        }
    };

    if let Err(err) = users::create_user(
        state.db(),
        &normalized_username,
        &password_hash,
        form.is_admin.is_some(),
    )
    .await
    {
        if is_unique_violation(&err) {
            field_errors.username = Some("That username is already taken.".to_string());
            return render_user_management_page(
                &state,
                &session,
                StatusCode::UNPROCESSABLE_ENTITY,
                users_snapshot,
                add_form,
                field_errors,
                Some("Unable to create the user.".to_string()),
                None,
            )
            .await;
        }

        error!(target: "users", %err, "failed to insert new user from admin panel");
        return server_error_response();
    }

    if let Err(err) = csrf::rotate_csrf_token(&session).await {
        error!(target: "csrf", %err, "failed to rotate CSRF token after adding user");
    }

    info!(
        target: "users",
        admin_id = admin.id,
        admin_username = %admin.username,
        new_username = %normalized_username,
        is_admin = form.is_admin.is_some(),
        "administrator created new user"
    );

    match fetch_user_rows(&state).await {
        Ok(users) => {
            render_user_management_page(
                &state,
                &session,
                StatusCode::OK,
                users,
                AddUserFormValues::default(),
                AddUserFieldErrors::default(),
                None,
                Some("User created successfully.".to_string()),
            )
            .await
        }
        Err(response) => response,
    }
}

pub async fn user_reset_password_handler(
    State(state): State<AppState>,
    session: Session,
    AxumPath(user_id): AxumPath<i64>,
    Form(form): Form<ResetUserPasswordForm>,
) -> Response {
    let admin = match require_admin(&session).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let csrf_valid = match csrf::validate_csrf_token(&session, &form.csrf_token).await {
        Ok(valid) => valid,
        Err(err) => {
            error!(target: "csrf", %err, "failed to validate CSRF token for password reset");
            return server_error_response();
        }
    };

    if !csrf_valid {
        warn!(target: "csrf", user_id = admin.id, "reset-password request failed CSRF validation");
        if let Err(err) = csrf::rotate_csrf_token(&session).await {
            error!(target: "csrf", %err, "failed to rotate CSRF token after reset-password failure");
        }
        return match fetch_user_rows(&state).await {
            Ok(users) => {
                render_user_management_page(
                    &state,
                    &session,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    users,
                    AddUserFormValues::default(),
                    AddUserFieldErrors::default(),
                    Some("Your session expired. Please try again.".to_string()),
                    None,
                )
                .await
            }
            Err(response) => response,
        };
    }

    if form.new_password != form.confirm_password {
        return match fetch_user_rows(&state).await {
            Ok(users) => {
                render_user_management_page(
                    &state,
                    &session,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    users,
                    AddUserFormValues::default(),
                    AddUserFieldErrors::default(),
                    Some("Passwords do not match.".to_string()),
                    None,
                )
                .await
            }
            Err(response) => response,
        };
    }

    if let Err(err) = validate_password_strength(&form.new_password) {
        match err {
            AuthError::InvalidPassword => {
                return match fetch_user_rows(&state).await {
                    Ok(users) => {
                        render_user_management_page(
                            &state,
                            &session,
                            StatusCode::UNPROCESSABLE_ENTITY,
                            users,
                            AddUserFormValues::default(),
                            AddUserFieldErrors::default(),
                            Some("Password must be at least 12 characters long.".to_string()),
                            None,
                        )
                        .await
                    }
                    Err(response) => response,
                };
            }
            _ => {
                error!(target: "auth", %err, "unexpected password validation error during reset");
                return server_error_response();
            }
        }
    }

    let target_user = match users::find_user_by_id(state.db(), user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return match fetch_user_rows(&state).await {
                Ok(users) => {
                    render_user_management_page(
                        &state,
                        &session,
                        StatusCode::NOT_FOUND,
                        users,
                        AddUserFormValues::default(),
                        AddUserFieldErrors::default(),
                        Some("That user no longer exists.".to_string()),
                        None,
                    )
                    .await
                }
                Err(response) => response,
            };
        }
        Err(err) => {
            error!(target: "users", %err, user_id, "failed to load user for password reset");
            return server_error_response();
        }
    };

    let new_hash = match hash_password(
        &form.new_password,
        state.config().security.password_pepper.as_deref(),
    )
    .await
    {
        Ok(hash) => hash,
        Err(err) => {
            error!(target: "auth", %err, "failed to hash password during admin reset");
            return server_error_response();
        }
    };

    if let Err(err) = update_password_hash(state.db(), target_user.id, &new_hash).await {
        error!(target: "auth", %err, user_id = target_user.id, "failed to update password hash during reset");
        return server_error_response();
    }

    if let Err(err) = csrf::rotate_csrf_token(&session).await {
        error!(target: "csrf", %err, "failed to rotate CSRF token after password reset");
    }

    info!(
        target: "users",
        admin_id = admin.id,
        admin_username = %admin.username,
        target_id = target_user.id,
        target_username = %target_user.username,
        "administrator reset user password"
    );

    match fetch_user_rows(&state).await {
        Ok(users) => {
            render_user_management_page(
                &state,
                &session,
                StatusCode::OK,
                users,
                AddUserFormValues::default(),
                AddUserFieldErrors::default(),
                None,
                Some(format!(
                    "Password reset for user '{}'.",
                    target_user.username
                )),
            )
            .await
        }
        Err(response) => response,
    }
}

pub async fn user_delete_handler(
    State(state): State<AppState>,
    session: Session,
    AxumPath(user_id): AxumPath<i64>,
    Form(form): Form<DeleteUserForm>,
) -> Response {
    let admin = match require_admin(&session).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let csrf_valid = match csrf::validate_csrf_token(&session, &form.csrf_token).await {
        Ok(valid) => valid,
        Err(err) => {
            error!(target: "csrf", %err, "failed to validate CSRF token for delete-user");
            return server_error_response();
        }
    };

    if !csrf_valid {
        warn!(target: "csrf", user_id = admin.id, "delete-user request failed CSRF validation");
        if let Err(err) = csrf::rotate_csrf_token(&session).await {
            error!(target: "csrf", %err, "failed to rotate CSRF token after delete-user failure");
        }
        return match fetch_user_rows(&state).await {
            Ok(users) => {
                render_user_management_page(
                    &state,
                    &session,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    users,
                    AddUserFormValues::default(),
                    AddUserFieldErrors::default(),
                    Some("Your session expired. Please try again.".to_string()),
                    None,
                )
                .await
            }
            Err(response) => response,
        };
    }

    let target_user = match users::find_user_by_id(state.db(), user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return match fetch_user_rows(&state).await {
                Ok(users) => {
                    render_user_management_page(
                        &state,
                        &session,
                        StatusCode::NOT_FOUND,
                        users,
                        AddUserFormValues::default(),
                        AddUserFieldErrors::default(),
                        Some("That user no longer exists.".to_string()),
                        None,
                    )
                    .await
                }
                Err(response) => response,
            };
        }
        Err(err) => {
            error!(target: "users", %err, user_id, "failed to load user for deletion");
            return server_error_response();
        }
    };

    if target_user.id == admin.id {
        return match fetch_user_rows(&state).await {
            Ok(users) => {
                render_user_management_page(
                    &state,
                    &session,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    users,
                    AddUserFormValues::default(),
                    AddUserFieldErrors::default(),
                    Some("You cannot delete your own account.".to_string()),
                    None,
                )
                .await
            }
            Err(response) => response,
        };
    }

    if target_user.is_admin {
        match users::count_admin_users(state.db()).await {
            Ok(count) if count <= 1 => {
                return match fetch_user_rows(&state).await {
                    Ok(users) => {
                        render_user_management_page(
                            &state,
                            &session,
                            StatusCode::UNPROCESSABLE_ENTITY,
                            users,
                            AddUserFormValues::default(),
                            AddUserFieldErrors::default(),
                            Some("At least one administrator must remain.".to_string()),
                            None,
                        )
                        .await
                    }
                    Err(response) => response,
                };
            }
            Ok(_) => {}
            Err(err) => {
                error!(target: "users", %err, "failed to count admin users before deletion");
                return server_error_response();
            }
        }
    }

    match users::delete_user(state.db(), target_user.id).await {
        Ok(affected) if affected == 1 => {}
        Ok(_) => {
            return server_error_response();
        }
        Err(err) => {
            error!(target: "users", %err, user_id = target_user.id, "failed to delete user");
            return server_error_response();
        }
    }

    if let Err(err) = csrf::rotate_csrf_token(&session).await {
        error!(target: "csrf", %err, "failed to rotate CSRF token after user deletion");
    }

    info!(
        target: "users",
        admin_id = admin.id,
        admin_username = %admin.username,
        target_id = target_user.id,
        target_username = %target_user.username,
        "administrator deleted user"
    );

    match fetch_user_rows(&state).await {
        Ok(users) => {
            render_user_management_page(
                &state,
                &session,
                StatusCode::OK,
                users,
                AddUserFormValues::default(),
                AddUserFieldErrors::default(),
                None,
                Some(format!("User '{}' deleted.", target_user.username)),
            )
            .await
        }
        Err(response) => response,
    }
}

async fn render_user_management_page(
    state: &AppState,
    session: &Session,
    status: StatusCode,
    users: Vec<users::UserSummary>,
    add_form: AddUserFormValues,
    add_errors: AddUserFieldErrors,
    general_error: Option<String>,
    success_message: Option<String>,
) -> Response {
    let layout = layout_from_session(state, session, "User management").await;

    let mapped_users = users
        .into_iter()
        .filter_map(map_user_summary_for_admin)
        .collect::<Vec<_>>();

    let mut template = UserManagementTemplate::new(layout, mapped_users)
        .with_add_form(add_form)
        .with_add_errors(add_errors);

    if let Some(message) = general_error {
        template = template.with_general_error(message);
    }

    if let Some(message) = success_message {
        template = template.with_success_message(message);
    }

    (status, HtmlTemplate::new(template)).into_response()
}

async fn fetch_user_rows(state: &AppState) -> Result<Vec<users::UserSummary>, Response> {
    match users::list_users(state.db()).await {
        Ok(rows) => Ok(rows),
        Err(err) => {
            error!(target: "users", %err, "failed to load users for management page");
            Err(server_error_response())
        }
    }
}

fn map_user_summary_for_admin(record: users::UserSummary) -> Option<ManagedUserRow> {
    let created_display = match time::OffsetDateTime::from_unix_timestamp(record.created_at) {
        Ok(dt) => format_datetime_utc(dt),
        Err(err) => {
            debug!(
                target: "users",
                %err,
                created_at = record.created_at,
                user_id = record.id,
                "invalid created_at stored for user"
            );
            return None;
        }
    };

    let last_login_display = match record.last_login_at {
        Some(ts) => match time::OffsetDateTime::from_unix_timestamp(ts) {
            Ok(dt) => Some(format_datetime_utc(dt)),
            Err(err) => {
                debug!(
                    target: "users",
                    %err,
                    last_login_at = ts,
                    user_id = record.id,
                    "invalid last_login_at stored for user"
                );
                None
            }
        },
        None => None,
    };

    Some(ManagedUserRow {
        id: record.id,
        username: record.username,
        is_admin: record.is_admin,
        created_display,
        last_login_display,
    })
}
