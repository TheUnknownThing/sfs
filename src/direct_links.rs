use std::sync::Arc;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use time::OffsetDateTime;

const MIN_SECRET_LEN: usize = 32;
const MAX_TOKEN_LENGTH: usize = 512;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("download token secret is too short")]
    SecretTooShort,
    #[error("failed to decode download token secret: {0}")]
    SecretDecode(String),
    #[error("token format is invalid")]
    InvalidFormat,
    #[error("token data is invalid")]
    InvalidData,
    #[error("token signature is invalid")]
    InvalidSignature,
    #[error("token has expired")]
    Expired,
}

#[derive(Clone)]
pub struct DownloadTokenService {
    secret: Arc<[u8]>,
}

#[derive(Debug, Clone)]
pub struct DownloadTokenClaims {
    pub file_id: String,
    pub expires_at: OffsetDateTime,
}

impl DownloadTokenService {
    pub fn from_config(secret: &str) -> Result<Self, TokenError> {
        let secret_bytes = resolve_secret_bytes(secret)?;
        Ok(Self {
            secret: Arc::from(secret_bytes.into_boxed_slice()),
        })
    }

    pub fn issue(&self, file_id: &str, expires_at: OffsetDateTime) -> Result<String, TokenError> {
        if file_id.trim().is_empty() {
            return Err(TokenError::InvalidData);
        }

        let exp_epoch = expires_at.unix_timestamp();
        let exp_segment = exp_epoch.to_string();

        let mut mac =
            HmacSha256::new_from_slice(&self.secret).map_err(|_| TokenError::SecretTooShort)?;
        mac.update(file_id.as_bytes());
        mac.update(exp_segment.as_bytes());
        let signature = mac.finalize().into_bytes();

        let id_part = URL_SAFE_NO_PAD.encode(file_id.as_bytes());
        let exp_part = URL_SAFE_NO_PAD.encode(exp_segment.as_bytes());
        let sig_part = URL_SAFE_NO_PAD.encode(signature);

        Ok(format!("{id_part}.{exp_part}.{sig_part}"))
    }

    pub fn parse(
        &self,
        token: &str,
        now: OffsetDateTime,
    ) -> Result<DownloadTokenClaims, TokenError> {
        if token.len() > MAX_TOKEN_LENGTH {
            return Err(TokenError::InvalidFormat);
        }

        let segments: Vec<&str> = token.split('.').collect();
        if segments.len() != 3 {
            return Err(TokenError::InvalidFormat);
        }

        let file_id_bytes = URL_SAFE_NO_PAD
            .decode(segments[0])
            .map_err(|_| TokenError::InvalidFormat)?;
        let file_id = String::from_utf8(file_id_bytes).map_err(|_| TokenError::InvalidData)?;
        if file_id.trim().is_empty() {
            return Err(TokenError::InvalidData);
        }

        let expires_bytes = URL_SAFE_NO_PAD
            .decode(segments[1])
            .map_err(|_| TokenError::InvalidFormat)?;
        let expires_str = String::from_utf8(expires_bytes).map_err(|_| TokenError::InvalidData)?;
        let exp_epoch: i64 = expires_str.parse().map_err(|_| TokenError::InvalidData)?;
        let expires_at =
            OffsetDateTime::from_unix_timestamp(exp_epoch).map_err(|_| TokenError::InvalidData)?;

        let supplied_signature = URL_SAFE_NO_PAD
            .decode(segments[2])
            .map_err(|_| TokenError::InvalidFormat)?;

        let mut mac =
            HmacSha256::new_from_slice(&self.secret).map_err(|_| TokenError::SecretTooShort)?;
        mac.update(file_id.as_bytes());
        mac.update(expires_str.as_bytes());
        let expected_signature = mac.finalize().into_bytes();

        if supplied_signature.len() != expected_signature.len()
            || supplied_signature
                .as_slice()
                .ct_eq(expected_signature.as_ref())
                .unwrap_u8()
                != 1
        {
            return Err(TokenError::InvalidSignature);
        }

        if expires_at <= now {
            return Err(TokenError::Expired);
        }

        Ok(DownloadTokenClaims {
            file_id,
            expires_at,
        })
    }
}

fn resolve_secret_bytes(secret: &str) -> Result<Vec<u8>, TokenError> {
    let trimmed = secret.trim();
    if trimmed.is_empty() {
        return Err(TokenError::SecretTooShort);
    }

    let bytes = if let Some(rest) = trimmed.strip_prefix("base64:") {
        STANDARD
            .decode(rest)
            .map_err(|err| TokenError::SecretDecode(err.to_string()))?
    } else {
        trimmed.as_bytes().to_vec()
    };

    if bytes.len() < MIN_SECRET_LEN {
        return Err(TokenError::SecretTooShort);
    }

    Ok(bytes)
}
