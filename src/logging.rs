use std::env;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub fn init_logging() -> Result<(), Box<dyn std::error::Error>> {
    // Default log level
    let default_filter = "info,simple_file_server=info";

    // Get log filter from environment or use default
    let filter = match EnvFilter::try_from_default_env() {
        Ok(filter) => filter,
        Err(_) => EnvFilter::try_new(default_filter)?,
    };

    // Check if JSON logging is requested
    let json_logging = env::var("LOG_JSON").unwrap_or_else(|_| "false".to_string()) == "true";

    if json_logging {
        // Production: JSON format
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json())
            .init();
    } else {
        // Development: Pretty format
        tracing_subscriber::registry()
            .with(filter)
            .with(
                fmt::layer()
                    .pretty()
                    .with_thread_ids(true)
                    .with_thread_names(true)
                    .with_file(true)
                    .with_line_number(true),
            )
            .init();
    }

    Ok(())
}
