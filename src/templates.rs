use askama::Template;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use time::OffsetDateTime;
use tracing::error;

use crate::app_state::AppState;

/// Shared layout context injected into all templates
#[derive(Clone, Debug)]
pub struct LayoutContext {
    pub title: String,
    pub brand_name: String,
    pub csrf: Option<CsrfMeta>,
    pub current_year: i32,
}

/// CSRF metadata exposed to templates
#[derive(Clone, Debug)]
pub struct CsrfMeta {
    pub token: String,
}

impl LayoutContext {
    /// Build a layout context using the configured brand name
    pub fn from_state(state: &AppState, title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            brand_name: state.config().ui.brand_name.clone(),
            csrf: None,
            current_year: OffsetDateTime::now_utc().year(),
        }
    }

    /// Attach a CSRF token that will be emitted in the base layout
    pub fn with_csrf_token(mut self, token: Option<String>) -> Self {
        self.csrf = token.map(|token| CsrfMeta { token });
        self
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
}

impl HomeTemplate {
    pub fn new(layout: LayoutContext) -> Self {
        Self { layout }
    }
}

#[derive(Template)]
#[template(path = "login.html", escape = "html")]
pub struct LoginTemplate {
    pub layout: LayoutContext,
}

impl LoginTemplate {
    pub fn new(layout: LayoutContext) -> Self {
        Self { layout }
    }
}

#[allow(dead_code)]
#[derive(Template)]
#[template(path = "upload.html", escape = "html")]
pub struct UploadTemplate {
    pub layout: LayoutContext,
}

impl UploadTemplate {
    #[allow(dead_code)]
    pub fn new(layout: LayoutContext) -> Self {
        Self { layout }
    }
}

#[allow(dead_code)]
#[derive(Template)]
#[template(path = "file.html", escape = "html")]
pub struct FileTemplate {
    pub layout: LayoutContext,
}

impl FileTemplate {
    #[allow(dead_code)]
    pub fn new(layout: LayoutContext) -> Self {
        Self { layout }
    }
}

#[allow(dead_code)]
#[derive(Template)]
#[template(path = "settings.html", escape = "html")]
pub struct SettingsTemplate {
    pub layout: LayoutContext,
}

impl SettingsTemplate {
    #[allow(dead_code)]
    pub fn new(layout: LayoutContext) -> Self {
        Self { layout }
    }
}
