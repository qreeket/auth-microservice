use env_logger;
use env_logger::{Builder, fmt::Color};
use log::{Level, LevelFilter};

use std::io::Write;

// custom logging formatter
pub(crate) fn init_logging() {
    // Initialize logger
    let mut builder = Builder::new();
    builder.filter_level(LevelFilter::Info);
    builder.format(|buf, record| {
        let level = record.level();
        let mut style = buf.style();
        match level {
            Level::Error => style.set_color(Color::Red),
            Level::Warn => style.set_color(Color::Yellow),
            Level::Info => style.set_color(Color::Green),
            Level::Debug => style.set_color(Color::Blue),
            Level::Trace => style.set_color(Color::Cyan),
        };
        writeln!(buf, "[{}] {}", style.value(level), record.args())
    });
    builder.init();
}