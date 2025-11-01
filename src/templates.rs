use askama::Template;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use time::OffsetDateTime;
use tracing::error;

use crate::{
    app_state::AppState,
    csrf,
    sessions::{self, SessionUser},
    settings::AppSettings,
};
use tower_sessions::{session::Error as SessionError, Session};

/// Shared layout context injected into all templates
#[derive(Clone, Debug)]
pub struct LayoutContext {
    pub title: String,
    pub brand_name: String,
    pub csrf: Option<CsrfMeta>,
    pub current_year: i32,
    pub current_user: Option<CurrentUserMeta>,
}

/// CSRF metadata exposed to templates
#[derive(Clone, Debug)]
pub struct CsrfMeta {
    pub token: String,
}

/// Lightweight view of the authenticated user for the layout.
#[derive(Clone, Debug)]
pub struct CurrentUserMeta {
    #[allow(dead_code)]
    pub id: i64,
    pub username: String,
    pub is_admin: bool,
}

impl LayoutContext {
    /// Build a layout context using the configured brand name
    pub async fn from_state(state: &AppState, title: impl Into<String>) -> Self {
        let brand_name = match state.settings().current().await {
            Ok(settings) => settings.ui_brand_name.clone(),
            Err(err) => {
                error!(
                    target: "settings",
                    %err,
                    "failed to load settings for layout; using configured fallback"
                );
                state.config().ui.brand_name.clone()
            }
        };

        Self {
            title: title.into(),
            brand_name,
            csrf: None,
            current_year: OffsetDateTime::now_utc().year(),
            current_user: None,
        }
    }

    /// Attach a CSRF token that will be emitted in the base layout
    pub fn with_csrf_token(mut self, token: Option<String>) -> Self {
        self.csrf = token.map(|token| CsrfMeta { token });
        self
    }

    /// Attach the current authenticated user information.
    pub fn with_current_user(mut self, user: Option<SessionUser>) -> Self {
        self.current_user = user.map(|user| CurrentUserMeta {
            id: user.id,
            username: user.username,
            is_admin: user.is_admin,
        });
        self
    }

    /// Construct a layout context using session-derived metadata.
    pub async fn from_session(
        state: &AppState,
        session: &Session,
        title: impl Into<String>,
    ) -> Result<Self, SessionError> {
        let csrf_token = csrf::ensure_csrf_token(session).await?;
        let user = sessions::current_user(session).await?;

        let layout = Self::from_state(state, title).await;

        Ok(layout
            .with_csrf_token(Some(csrf_token))
            .with_current_user(user))
    }
}

/// Wrapper that converts Askama templates into Axum responses with logging
pub struct HtmlTemplate<T: Template> {
    template: T,
    status: StatusCode,
}

impl<T: Template> HtmlTemplate<T> {
    pub fn new(template: T) -> Self {
        Self {
            template,
            status: StatusCode::OK,
        }
    }

    #[allow(dead_code)]
    pub fn with_status(template: T, status: StatusCode) -> Self {
        Self { template, status }
    }
}

impl<T: Template> From<T> for HtmlTemplate<T> {
    fn from(template: T) -> Self {
        Self::new(template)
    }
}

impl<T: Template> IntoResponse for HtmlTemplate<T> {
    fn into_response(self) -> Response {
        match self.template.render() {
            Ok(html) => (self.status, Html(html)).into_response(),
            Err(err) => {
                error!(target: "templates", error = %err, "failed to render template");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Template rendering error",
                )
                    .into_response()
            }
        }
    }
}

#[derive(Template)]
#[template(path = "home.html", escape = "html")]
pub struct HomeTemplate {
    pub layout: LayoutContext,
    pub recent_uploads: Vec<HomeUploadRow>,
}

impl HomeTemplate {
    pub fn new(layout: LayoutContext) -> Self {
        Self {
            layout,
            recent_uploads: Vec::new(),
        }
    }

    pub fn with_recent_uploads(mut self, uploads: Vec<HomeUploadRow>) -> Self {
        self.recent_uploads = uploads;
        self
    }
}

#[derive(Template)]
#[template(path = "login.html", escape = "html")]
pub struct LoginTemplate {
    pub layout: LayoutContext,
    pub error_message: Option<String>,
    pub username: String,
}

impl LoginTemplate {
    pub fn new(layout: LayoutContext) -> Self {
        Self {
            layout,
            error_message: None,
            username: String::new(),
        }
    }

    pub fn with_error_message(mut self, message: impl Into<String>) -> Self {
        self.error_message = Some(message.into());
        self
    }

    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = username.into();
        self
    }
}

#[derive(Template)]
#[template(path = "upload.html", escape = "html")]
pub struct UploadTemplate {
    pub layout: LayoutContext,
    pub max_file_size_display: String,
    pub max_expiration_hours: u64,
    pub expires_in_value: String,
    pub error_message: Option<String>,
}

impl UploadTemplate {
    pub fn new(
        layout: LayoutContext,
        max_file_size_display: impl Into<String>,
        max_expiration_hours: u64,
        expires_in_value: impl Into<String>,
    ) -> Self {
        Self {
            layout,
            max_file_size_display: max_file_size_display.into(),
            max_expiration_hours,
            expires_in_value: expires_in_value.into(),
            error_message: None,
        }
    }

    pub fn with_error_message(mut self, message: impl Into<String>) -> Self {
        self.error_message = Some(message.into());
        self
    }
}

#[derive(Clone, Debug)]
pub struct HomeUploadRow {
    pub code: String,
    pub original_name: String,
    pub size_display: String,
    pub created_display: String,
}

#[derive(Template)]
#[template(path = "file.html", escape = "html")]
pub struct FileTemplate {
    pub layout: LayoutContext,
    pub code: String,
    pub original_name: String,
    pub size_display: String,
    pub created_display: String,
    pub expires_display: Option<String>,
    pub content_type: Option<String>,
    pub checksum: Option<String>,
}

impl FileTemplate {
    pub fn new(
        layout: LayoutContext,
        code: impl Into<String>,
        original_name: impl Into<String>,
        size_display: impl Into<String>,
        created_display: impl Into<String>,
        expires_display: Option<String>,
    ) -> Self {
        Self {
            layout,
            code: code.into(),
            original_name: original_name.into(),
            size_display: size_display.into(),
            created_display: created_display.into(),
            expires_display,
            content_type: None,
            checksum: None,
        }
    }

    pub fn with_content_type(mut self, content_type: Option<String>) -> Self {
        self.content_type = content_type;
        self
    }

    pub fn with_checksum(mut self, checksum: Option<String>) -> Self {
        self.checksum = checksum;
        self
    }
}

#[derive(Template)]
#[template(path = "direct_link_snippet.html", escape = "html")]
pub struct DirectLinkSnippetTemplate {
    pub link: String,
    pub expires_display: String,
    pub ttl_minutes: u64,
    pub input_id: String,
}

impl DirectLinkSnippetTemplate {
    pub fn new(
        link: impl Into<String>,
        expires_display: impl Into<String>,
        ttl_minutes: u64,
    ) -> Self {
        Self {
            link: link.into(),
            expires_display: expires_display.into(),
            ttl_minutes,
            input_id: "direct-link-url".to_string(),
        }
    }

    pub fn with_input_id(mut self, input_id: impl Into<String>) -> Self {
        self.input_id = input_id.into();
        self
    }
}

#[derive(Template)]
#[template(path = "direct_link_error.html", escape = "html")]
pub struct DirectLinkErrorTemplate {
    pub message: String,
}

impl DirectLinkErrorTemplate {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Template)]
#[template(path = "settings.html", escape = "html")]
pub struct SettingsTemplate {
    pub layout: LayoutContext,
    pub form: SettingsFormValues,
    pub field_errors: SettingsFieldErrors,
    pub general_error: Option<String>,
    pub success_message: Option<String>,
}

impl SettingsTemplate {
    pub fn new(layout: LayoutContext, form: SettingsFormValues) -> Self {
        Self {
            layout,
            form,
            field_errors: SettingsFieldErrors::default(),
            general_error: None,
            success_message: None,
        }
    }

    pub fn with_field_errors(mut self, field_errors: SettingsFieldErrors) -> Self {
        self.field_errors = field_errors;
        self
    }

    pub fn with_general_error(mut self, message: impl Into<String>) -> Self {
        self.general_error = Some(message.into());
        self
    }

    pub fn with_success_message(mut self, message: impl Into<String>) -> Self {
        self.success_message = Some(message.into());
        self
    }
}

#[derive(Clone, Debug)]
pub struct SettingsFormValues {
    pub max_file_size_bytes: String,
    pub default_expiration_hours: String,
    pub direct_link_ttl_minutes: String,
    pub allow_anonymous_download: bool,
    pub ui_brand_name: String,
}

impl SettingsFormValues {
    pub fn from_settings(settings: &AppSettings) -> Self {
        Self {
            max_file_size_bytes: settings.max_file_size_bytes.to_string(),
            default_expiration_hours: settings.default_expiration_hours.to_string(),
            direct_link_ttl_minutes: settings.direct_link_ttl_minutes.to_string(),
            allow_anonymous_download: settings.allow_anonymous_download,
            ui_brand_name: settings.ui_brand_name.clone(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct SettingsFieldErrors {
    pub max_file_size_bytes: Option<String>,
    pub default_expiration_hours: Option<String>,
    pub direct_link_ttl_minutes: Option<String>,
    pub ui_brand_name: Option<String>,
}
