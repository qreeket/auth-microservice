extern crate dotenv;
#[macro_use]
extern crate rust_i18n;

mod config;
pub mod server;
pub mod utils;
pub mod client;

pub(crate) mod proto {
    tonic::include_proto!("qreeket");

    pub(crate) const AUTH_FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("auth_descriptor");
}

i18n!("locales");

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // load .env file
    dotenv::dotenv().ok();

    // initialize logging
    config::logging::init_logging();

    // initialize tracing with sentry
    config::tracing::init_tracing();

    // setup grpc server
    config::server::init_server().await?;

    Ok(())
}
