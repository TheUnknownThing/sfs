use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;
use tower_sessions::Session;
use tracing::{error, info, warn};

use crate::{
    app_state::AppState,
    auth::{
        find_user_by_username, hash_password, normalize_username, randomized_backoff,
        touch_user_login, update_password_hash, validate_password_strength, verify_password,
        AuthError,
    },
    csrf,
    rate_limit::RateLimitError,
    sessions::{clear_user, current_user, store_user, SessionUser},
    templates::{
        HtmlTemplate, LayoutContext, LoginTemplate, RegisterTemplate, RegistrationFieldErrors,
        RegistrationFormValues,
    },
    users,
};

use crate::server::utils::{attach_retry_after, is_unique_violation, server_error_response};

use super::shared::{current_app_settings, layout_from_session};

#[derive(Debug, Deserialize)]
pub(crate) struct LoginForm {
    csrf_token: String,
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RegistrationForm {
    csrf_token: String,
    username: String,
    password: String,
    password_confirm: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LogoutForm {
    csrf_token: String,
}

pub async fn login_form_handler(State(state): State<AppState>, session: Session) -> Response {
    match current_user(&session).await {
        Ok(Some(_)) => Redirect::to("/").into_response(),
        Ok(None) => {
            let layout = layout_from_session(&state, &session, "Sign in").await;
            HtmlTemplate::new(LoginTemplate::new(layout)).into_response()
        }
        Err(err) => {
            error!(target: "auth", %err, "failed to read user from session");
            let layout = LayoutContext::from_state(&state, "Sign in").await;
            HtmlTemplate::new(LoginTemplate::new(layout)).into_response()
        }
    }
}

pub async fn login_submit_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    session: Session,
    Form(form): Form<LoginForm>,
) -> Response {
    const INVALID_CREDENTIALS_MESSAGE: &str = "Invalid username or password.";

    let client_ip = addr.ip();

    if let Err(err) = state.login_rate_limiter().check_ip(client_ip) {
        warn!(target: "auth", ip = %client_ip, %err, "rate limited login by IP");
        return rate_limited_login_response(&state, &session, &form.username, &err).await;
    }

    let normalized_username = match normalize_username(&form.username) {
        Ok(username) => username,
        Err(_) => {
            randomized_backoff().await;
            return render_login_page(
                &state,
                &session,
                &form.username,
                Some(INVALID_CREDENTIALS_MESSAGE.to_string()),
                StatusCode::UNAUTHORIZED,
            )
            .await;
        }
    };

    if let Err(err) = state
        .login_rate_limiter()
        .check_username(&normalized_username)
    {
        warn!(target: "auth", username = %normalized_username, %err, "rate limited login by username");
        return rate_limited_login_response(&state, &session, &form.username, &err).await;
    }

    let csrf_valid = match csrf::validate_csrf_token(&session, &form.csrf_token).await {
        Ok(valid) => valid,
        Err(err) => {
            error!(target: "auth", %err, "failed to validate CSRF token");
            return server_error_response();
        }
    };

    if !csrf_valid {
        warn!(target: "auth", username = %normalized_username, "invalid CSRF token on login");
        if let Err(err) = csrf::rotate_csrf_token(&session).await {
            error!(target: "auth", %err, "failed to rotate CSRF token after validation error");
        }
        randomized_backoff().await;
        return render_login_page(
            &state,
            &session,
            &form.username,
            Some("Your session expired. Please try again.".to_string()),
            StatusCode::UNPROCESSABLE_ENTITY,
        )
        .await;
    }

    let maybe_user = match find_user_by_username(state.db(), &normalized_username).await {
        Ok(user) => user,
        Err(err) => {
            error!(target: "auth", %err, "failed to load user during login");
            return server_error_response();
        }
    };

    let user = match maybe_user {
        Some(user) => user,
        None => {
            randomized_backoff().await;
            return render_login_page(
                &state,
                &session,
                &form.username,
                Some(INVALID_CREDENTIALS_MESSAGE.to_string()),
                StatusCode::UNAUTHORIZED,
            )
            .await;
        }
    };

    let verification = match verify_password(
        &form.password,
        &user.password_hash,
        state.config().security.password_pepper.as_deref(),
    )
    .await
    {
        Ok(result) => result,
        Err(AuthError::InvalidCredentials) => {
            randomized_backoff().await;
            return render_login_page(
                &state,
                &session,
                &form.username,
                Some(INVALID_CREDENTIALS_MESSAGE.to_string()),
                StatusCode::UNAUTHORIZED,
            )
            .await;
        }
        Err(err) => {
            error!(target: "auth", %err, "error verifying password");
            return server_error_response();
        }
    };

    if verification.needs_rehash {
        match hash_password(
            &form.password,
            state.config().security.password_pepper.as_deref(),
        )
        .await
        {
            Ok(new_hash) => {
                if let Err(err) = update_password_hash(state.db(), user.id, &new_hash).await {
                    error!(target: "auth", %err, "failed to update password hash during rehash");
                    if let Err(err) = touch_user_login(state.db(), user.id).await {
                        error!(target: "auth", %err, "failed to update last login timestamp");
                    }
                }
            }
            Err(err) => {
                error!(target: "auth", %err, "failed to rehash password");
                if let Err(err) = touch_user_login(state.db(), user.id).await {
                    error!(target: "auth", %err, "failed to update last login timestamp");
                }
            }
        }
    } else if let Err(err) = touch_user_login(state.db(), user.id).await {
        error!(target: "auth", %err, "failed to update last login timestamp");
    }

    if let Err(err) = session.cycle_id().await {
        error!(target: "auth", %err, "failed to cycle session ID on login");
        return server_error_response();
    }

    let session_user = SessionUser::new(user.id, user.username.clone(), user.is_admin);
    if let Err(err) = store_user(&session, &session_user).await {
        error!(target: "auth", %err, "failed to persist authenticated user in session");
        return server_error_response();
    }

    if let Err(err) = csrf::rotate_csrf_token(&session).await {
        error!(target: "auth", %err, "failed to rotate CSRF token after login");
    }

    Redirect::to("/").into_response()
}

pub async fn register_form_handler(State(state): State<AppState>, session: Session) -> Response {
    match current_user(&session).await {
        Ok(Some(_)) => return Redirect::to("/").into_response(),
        Ok(None) => {}
        Err(err) => {
            error!(
                target: "sessions",
                %err,
                "failed to read session while rendering registration form"
            );
            return server_error_response();
        }
    }

    let settings = match current_app_settings(&state).await {
        Ok(settings) => settings,
        Err(response) => return response,
    };

    if !settings.allow_registration {
        return registration_closed_response(&state, &session).await;
    }

    render_registration_form(
        &state,
        &session,
        StatusCode::OK,
        RegistrationFormValues::default(),
        RegistrationFieldErrors::default(),
        None,
    )
    .await
}

pub async fn register_submit_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    session: Session,
    Form(form): Form<RegistrationForm>,
) -> Response {
    match current_user(&session).await {
        Ok(Some(_)) => return Redirect::to("/").into_response(),
        Ok(None) => {}
        Err(err) => {
            error!(
                target: "sessions",
                %err,
                "failed to read session while processing registration"
            );
            return server_error_response();
        }
    }

    let settings = match current_app_settings(&state).await {
        Ok(settings) => settings,
        Err(response) => return response,
    };

    if !settings.allow_registration {
        return registration_closed_response(&state, &session).await;
    }

    let client_ip = addr.ip();
    if let Err(err) = state.registration_rate_limiter().check_ip(client_ip) {
        warn!(
            target: "auth",
            ip = %client_ip,
            %err,
            "registration request rate-limited"
        );
        let form_values = RegistrationFormValues {
            username: form.username.trim().to_string(),
        };
        return registration_rate_limited_response(&state, &session, form_values, &err).await;
    }

    let csrf_valid = match csrf::validate_csrf_token(&session, &form.csrf_token).await {
        Ok(valid) => valid,
        Err(err) => {
            error!(target: "csrf", %err, "failed to validate CSRF token on registration");
            return server_error_response();
        }
    };

    if !csrf_valid {
        warn!(target: "csrf", "registration form submitted with invalid CSRF token");
        if let Err(err) = csrf::rotate_csrf_token(&session).await {
            error!(target: "csrf", %err, "failed to rotate CSRF token after invalid registration");
        }
        let form_values = RegistrationFormValues {
            username: form.username.trim().to_string(),
        };
        return render_registration_form(
            &state,
            &session,
            StatusCode::UNPROCESSABLE_ENTITY,
            form_values,
            RegistrationFieldErrors::default(),
            Some("Your session expired. Please try again.".to_string()),
        )
        .await;
    }

    let mut field_errors = RegistrationFieldErrors::default();
    let mut has_errors = false;
    let username_input = form.username.trim();
    let form_values = RegistrationFormValues {
        username: username_input.to_string(),
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

    if normalized_username.is_empty() {
        return render_registration_form(
            &state,
            &session,
            StatusCode::UNPROCESSABLE_ENTITY,
            form_values,
            field_errors,
            Some("Please correct the highlighted fields.".to_string()),
        )
        .await;
    }

    if let Err(err) = validate_password_strength(&form.password) {
        match err {
            AuthError::InvalidPassword => {
                field_errors.password =
                    Some("Password must be at least 12 characters long.".to_string());
            }
            _ => {
                error!(target: "auth", %err, "unexpected validation error on password strength");
                return server_error_response();
            }
        }
        has_errors = true;
    }

    if form.password != form.password_confirm {
        field_errors.password_confirm = Some("Passwords do not match.".to_string());
        has_errors = true;
    }

    if has_errors {
        return render_registration_form(
            &state,
            &session,
            StatusCode::UNPROCESSABLE_ENTITY,
            form_values,
            field_errors,
            Some("Please correct the highlighted fields.".to_string()),
        )
        .await;
    }

    match find_user_by_username(state.db(), &normalized_username).await {
        Ok(Some(_)) => {
            let mut field_errors = RegistrationFieldErrors::default();
            field_errors.username = Some("That username is already taken.".to_string());
            return render_registration_form(
                &state,
                &session,
                StatusCode::UNPROCESSABLE_ENTITY,
                form_values,
                field_errors,
                Some("We couldn't create your account.".to_string()),
            )
            .await;
        }
        Ok(None) => {}
        Err(err) => {
            error!(target: "auth", %err, "failed to check username uniqueness during registration");
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
            error!(target: "auth", %err, "failed to hash password during registration");
            return server_error_response();
        }
    };

    if let Err(err) =
        users::create_user(state.db(), &normalized_username, &password_hash, false).await
    {
        if is_unique_violation(&err) {
            let mut field_errors = RegistrationFieldErrors::default();
            field_errors.username = Some("That username is already taken.".to_string());
            return render_registration_form(
                &state,
                &session,
                StatusCode::UNPROCESSABLE_ENTITY,
                form_values,
                field_errors,
                Some("We couldn't create your account.".to_string()),
            )
            .await;
        }

        error!(target: "auth", %err, "failed to create user during registration");
        return server_error_response();
    }

    let user = match find_user_by_username(state.db(), &normalized_username).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            error!(
                target: "auth",
                username = %normalized_username,
                "newly created user missing during registration lookup"
            );
            return server_error_response();
        }
        Err(err) => {
            error!(target: "auth", %err, "failed to reload user after registration");
            return server_error_response();
        }
    };

    if let Err(err) = touch_user_login(state.db(), user.id).await {
        warn!(target: "auth", %err, user_id = user.id, "failed to update last login after registration");
    }

    if let Err(err) = session.cycle_id().await {
        error!(target: "auth", %err, "failed to cycle session ID after registration");
        return server_error_response();
    }

    let session_user = SessionUser::new(user.id, user.username.clone(), user.is_admin);
    if let Err(err) = store_user(&session, &session_user).await {
        error!(target: "auth", %err, "failed to store new user in session");
        return server_error_response();
    }

    if let Err(err) = csrf::rotate_csrf_token(&session).await {
        error!(target: "csrf", %err, "failed to rotate CSRF token after registration");
    }

    info!(target: "auth", user_id = user.id, username = %user.username, "user registered successfully");

    Redirect::to("/").into_response()
}

pub async fn logout_handler(session: Session, Form(form): Form<LogoutForm>) -> Response {
    let csrf_valid = match csrf::validate_csrf_token(&session, &form.csrf_token).await {
        Ok(valid) => valid,
        Err(err) => {
            error!(target: "auth", %err, "failed to validate CSRF token on logout");
            return server_error_response();
        }
    };

    if !csrf_valid {
        warn!(target: "auth", "invalid CSRF token on logout");
        if let Err(err) = csrf::rotate_csrf_token(&session).await {
            error!(target: "auth", %err, "failed to rotate CSRF token after logout validation failure");
        }
        return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
    }

    if let Err(err) = clear_user(&session).await {
        error!(target: "auth", %err, "failed to clear user session on logout");
        return server_error_response();
    }

    if let Err(err) = csrf::rotate_csrf_token(&session).await {
        error!(target: "auth", %err, "failed to rotate CSRF token during logout");
    }

    if let Err(err) = session.cycle_id().await {
        error!(target: "auth", %err, "failed to cycle session after logout");
        return server_error_response();
    }

    Redirect::to("/login").into_response()
}

async fn render_login_page(
    state: &AppState,
    session: &Session,
    username: &str,
    error_message: Option<String>,
    status: StatusCode,
) -> Response {
    let mut template = LoginTemplate::new(layout_from_session(state, session, "Sign in").await)
        .with_username(username);
    if let Some(message) = error_message {
        template = template.with_error_message(message);
    }

    (status, HtmlTemplate::new(template)).into_response()
}

async fn render_registration_form(
    state: &AppState,
    session: &Session,
    status: StatusCode,
    form: RegistrationFormValues,
    field_errors: RegistrationFieldErrors,
    general_error: Option<String>,
) -> Response {
    let mut template = RegisterTemplate::new(layout_from_session(state, session, "Register").await)
        .with_form(form)
        .with_field_errors(field_errors);

    if let Some(message) = general_error {
        template = template.with_general_error(message);
    }

    (status, HtmlTemplate::new(template)).into_response()
}

async fn registration_closed_response(state: &AppState, session: &Session) -> Response {
    render_registration_form(
        state,
        session,
        StatusCode::FORBIDDEN,
        RegistrationFormValues::default(),
        RegistrationFieldErrors::default(),
        Some("Registration is currently disabled.".to_string()),
    )
    .await
}

async fn registration_rate_limited_response(
    state: &AppState,
    session: &Session,
    form: RegistrationFormValues,
    error: &RateLimitError,
) -> Response {
    let message = match error {
        RateLimitError::Registration(_) => {
            "Too many registration attempts from this IP. Please wait and try again.".to_string()
        }
        _ => "Too many requests right now. Please wait before trying again.".to_string(),
    };

    let mut response = render_registration_form(
        state,
        session,
        StatusCode::TOO_MANY_REQUESTS,
        form,
        RegistrationFieldErrors::default(),
        Some(message),
    )
    .await;

    attach_retry_after(&mut response, error.retry_after().as_secs());

    response
}

async fn rate_limited_login_response(
    state: &AppState,
    session: &Session,
    username: &str,
    error: &RateLimitError,
) -> Response {
    let message = match error {
        RateLimitError::Ip(_) => {
            "Too many login attempts from this IP address. Please wait and try again.".to_string()
        }
        RateLimitError::Username(_) => {
            "Too many login attempts for this username. Please wait before trying again."
                .to_string()
        }
        RateLimitError::DirectLink(_) | RateLimitError::DirectDownload(_) => {
            "Too many requests right now. Please wait before trying again.".to_string()
        }
        RateLimitError::Registration(_) => {
            "Too many requests right now. Please wait before trying again.".to_string()
        }
    };

    let mut response = render_login_page(
        state,
        session,
        username,
        Some(message),
        StatusCode::TOO_MANY_REQUESTS,
    )
    .await;

    attach_retry_after(&mut response, error.retry_after().as_secs());

    response
}
