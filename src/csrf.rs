use subtle::ConstantTimeEq;
use tower_sessions::{session::Error as SessionError, Session};

use crate::sessions::SESSION_CSRF_KEY;

/// Retrieve the CSRF token for the current session or generate a new one.
pub async fn ensure_csrf_token(session: &Session) -> Result<String, SessionError> {
    if let Some(token) = session.get::<String>(SESSION_CSRF_KEY).await? {
        return Ok(token);
    }

    let token = nanoid::nanoid!(64);
    session.insert(SESSION_CSRF_KEY, &token).await?;
    Ok(token)
}

/// Rotate the CSRF token for the current session.
pub async fn rotate_csrf_token(session: &Session) -> Result<String, SessionError> {
    let _ = session.remove::<String>(SESSION_CSRF_KEY).await?;
    ensure_csrf_token(session).await
}

/// Validate a provided CSRF token against the session-stored value.
pub async fn validate_csrf_token(session: &Session, provided: &str) -> Result<bool, SessionError> {
    let Some(expected) = session.get::<String>(SESSION_CSRF_KEY).await? else {
        return Ok(false);
    };

    Ok(expected.as_bytes().ct_eq(provided.as_bytes()).unwrap_u8() == 1)
}
