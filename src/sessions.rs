use serde::{Deserialize, Serialize};
use tower_sessions::{session::Error as SessionError, Session};

pub const SESSION_USER_KEY: &str = "auth.user";
pub const SESSION_CSRF_KEY: &str = "security.csrf";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionUser {
    pub id: i64,
    pub username: String,
    pub is_admin: bool,
}

impl SessionUser {
    pub fn new(id: i64, username: String, is_admin: bool) -> Self {
        Self {
            id,
            username,
            is_admin,
        }
    }
}

pub async fn store_user(session: &Session, user: &SessionUser) -> Result<(), SessionError> {
    session.insert(SESSION_USER_KEY, user).await
}

pub async fn clear_user(session: &Session) -> Result<(), SessionError> {
    let _ = session.remove::<SessionUser>(SESSION_USER_KEY).await?;
    Ok(())
}

pub async fn current_user(session: &Session) -> Result<Option<SessionUser>, SessionError> {
    session.get(SESSION_USER_KEY).await
}
