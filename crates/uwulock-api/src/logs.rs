//! The newest lines of the server's log, kept in memory for the admin portal.
//!
//! The server logs to stderr as before; this is a second copy of the last few thousand lines, so
//! an admin can look without a shell on the machine. Nothing in it is secret: the server never
//! logs a password, a token or anything from a vault.

use parking_lot::Mutex;
use serde::Serialize;
use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::Arc;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogLine {
    /// Counts up with every line, for asking only for what is new.
    pub seq: u64,
    /// When, in the database's time format.
    pub time: String,
    /// `error`, `warn`, `info`, `debug` or `trace`.
    pub level: &'static str,
    pub target: String,
    pub message: String,
}

pub struct LogBuffer {
    capacity: usize,
    lines: Mutex<(VecDeque<LogLine>, u64)>,
}

impl LogBuffer {
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(LogBuffer { capacity, lines: Mutex::new((VecDeque::with_capacity(capacity), 1)) })
    }

    /// A tracing layer that copies every event here.
    pub fn layer(self: &Arc<Self>) -> LogLayer {
        LogLayer(self.clone())
    }

    fn push(&self, mut line: LogLine) {
        let mut lines = self.lines.lock();
        line.seq = lines.1;
        lines.1 += 1;
        if lines.0.len() == self.capacity {
            lines.0.pop_front();
        }
        lines.0.push_back(line);
    }

    /// Lines after `after`, at least as severe as `level`, the newest `limit` of them, oldest first.
    pub fn lines(&self, after: u64, level: &str, limit: usize) -> Vec<LogLine> {
        let max = rank(level);
        let lines = self.lines.lock();
        let matching: Vec<&LogLine> =
            lines.0.iter().filter(|line| line.seq > after && rank(line.level) <= max).collect();
        let skip = matching.len().saturating_sub(limit);
        matching.into_iter().skip(skip).cloned().collect()
    }
}

fn rank(level: &str) -> u8 {
    match level {
        "error" => 0,
        "warn" => 1,
        "info" => 2,
        "debug" => 3,
        _ => 4,
    }
}

pub struct LogLayer(Arc<LogBuffer>);

impl<S: Subscriber> Layer<S> for LogLayer {
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        let level = match *event.metadata().level() {
            Level::ERROR => "error",
            Level::WARN => "warn",
            Level::INFO => "info",
            Level::DEBUG => "debug",
            Level::TRACE => "trace",
        };
        let mut visitor = Message::default();
        event.record(&mut visitor);
        self.0.push(LogLine {
            seq: 0,
            time: uwulock_store::clock::now(),
            level,
            target: event.metadata().target().to_string(),
            message: visitor.0,
        });
    }
}

/// The message first, then `key=value` for every other field.
#[derive(Default)]
struct Message(String);

impl Visit for Message {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let rest = std::mem::take(&mut self.0);
            let _ = write!(self.0, "{value:?}");
            if !rest.is_empty() {
                self.0.push(' ');
                self.0.push_str(&rest);
            }
        } else {
            if !self.0.is_empty() {
                self.0.push(' ');
            }
            let _ = write!(self.0, "{}={value:?}", field.name());
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.record_debug(field, &format_args!("{value}"));
        } else {
            if !self.0.is_empty() {
                self.0.push(' ');
            }
            let _ = write!(self.0, "{}={value}", field.name());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt;

    #[test]
    fn lines_are_kept_and_old_ones_go() {
        let buffer = LogBuffer::new(3);
        let subscriber = tracing_subscriber::registry().with(buffer.layer());
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(user = "u1", "logged in");
            tracing::warn!("slow disk");
            tracing::debug!("detail");
            tracing::error!(code = 5, "broken");
        });
        let all = buffer.lines(0, "trace", 100);
        assert_eq!(all.len(), 3, "only the newest three");
        assert_eq!(all[0].message, "slow disk");
        let warnings = buffer.lines(0, "warn", 100);
        assert_eq!(warnings.iter().map(|line| line.level).collect::<Vec<_>>(), ["warn", "error"]);
        assert_eq!(warnings[1].message, "broken code=5");
        assert!(buffer.lines(all[2].seq, "trace", 100).is_empty(), "nothing newer");
    }
}
