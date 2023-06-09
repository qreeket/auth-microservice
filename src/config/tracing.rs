// initialize tracing with sentry
pub(crate) fn init_tracing() {
    let sentry_dsn = std::env::var("SENTRY_DSN").expect("SENTRY_DSN must be set");
    let _ = sentry::init((sentry_dsn, sentry::ClientOptions {
        release: sentry::release_name!(),
        ..Default::default()
    }));
}