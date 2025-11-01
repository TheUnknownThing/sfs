use std::{net::IpAddr, num::NonZeroU32, time::Duration};

use governor::{
    clock::{Clock, DefaultClock},
    state::keyed::DashMapStateStore,
    Quota, RateLimiter,
};
use thiserror::Error;

const LINK_GENERATION_BURST: u32 = 5;
const DIRECT_DOWNLOAD_BURST: u32 = 30;

/// Rate limiter shared for login attempts.
pub struct LoginRateLimiter {
    ip_limiter: RateLimiter<IpAddr, DashMapStateStore<IpAddr>, DefaultClock>,
    username_limiter: RateLimiter<String, DashMapStateStore<String>, DefaultClock>,
}

impl LoginRateLimiter {
    pub fn new() -> Self {
        let burst = NonZeroU32::new(5).expect("burst must be non-zero");
        let quota = Quota::per_minute(burst);
        Self {
            ip_limiter: RateLimiter::keyed(quota),
            username_limiter: RateLimiter::keyed(quota),
        }
    }

    pub fn check_ip(&self, ip: IpAddr) -> Result<(), RateLimitError> {
        match self.ip_limiter.check_key(&ip) {
            Ok(_) => {
                self.ip_limiter.retain_recent();
                Ok(())
            }
            Err(not_until) => {
                let wait = not_until.wait_time_from(DefaultClock::default().now());
                Err(RateLimitError::Ip(wait))
            }
        }
    }

    pub fn check_username(&self, username: &str) -> Result<(), RateLimitError> {
        let key = username.to_owned();
        match self.username_limiter.check_key(&key) {
            Ok(_) => {
                self.username_limiter.retain_recent();
                Ok(())
            }
            Err(not_until) => {
                let wait = not_until.wait_time_from(DefaultClock::default().now());
                Err(RateLimitError::Username(wait))
            }
        }
    }
}

/// Rate limiter for temporary direct-link generation per client IP.
pub struct DirectLinkRateLimiter {
    limiter: RateLimiter<IpAddr, DashMapStateStore<IpAddr>, DefaultClock>,
}

impl DirectLinkRateLimiter {
    pub fn new() -> Self {
        let burst = NonZeroU32::new(LINK_GENERATION_BURST).expect("burst must be non-zero");
        let quota = Quota::per_minute(burst);
        Self {
            limiter: RateLimiter::keyed(quota),
        }
    }

    pub fn check_ip(&self, ip: IpAddr) -> Result<(), RateLimitError> {
        match self.limiter.check_key(&ip) {
            Ok(_) => {
                self.limiter.retain_recent();
                Ok(())
            }
            Err(not_until) => {
                let wait = not_until.wait_time_from(DefaultClock::default().now());
                Err(RateLimitError::DirectLink(wait))
            }
        }
    }
}

/// Rate limiter for direct download requests per client IP.
pub struct DirectDownloadRateLimiter {
    limiter: RateLimiter<IpAddr, DashMapStateStore<IpAddr>, DefaultClock>,
}

impl DirectDownloadRateLimiter {
    pub fn new() -> Self {
        let burst = NonZeroU32::new(DIRECT_DOWNLOAD_BURST).expect("burst must be non-zero");
        let quota = Quota::per_minute(burst);
        Self {
            limiter: RateLimiter::keyed(quota),
        }
    }

    pub fn check_ip(&self, ip: IpAddr) -> Result<(), RateLimitError> {
        match self.limiter.check_key(&ip) {
            Ok(_) => {
                self.limiter.retain_recent();
                Ok(())
            }
            Err(not_until) => {
                let wait = not_until.wait_time_from(DefaultClock::default().now());
                Err(RateLimitError::DirectDownload(wait))
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum RateLimitError {
    #[error("Too many attempts from this IP. Try again in {0:?}.")]
    Ip(Duration),
    #[error("Too many attempts for this username. Try again in {0:?}.")]
    Username(Duration),
    #[error("Too many direct link requests from this IP. Try again in {0:?}.")]
    DirectLink(Duration),
    #[error("Too many download requests from this IP. Try again in {0:?}.")]
    DirectDownload(Duration),
}

impl RateLimitError {
    pub fn retry_after(&self) -> Duration {
        match self {
            RateLimitError::Ip(duration)
            | RateLimitError::Username(duration)
            | RateLimitError::DirectLink(duration)
            | RateLimitError::DirectDownload(duration) => *duration,
        }
    }
}
