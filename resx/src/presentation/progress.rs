//! A transient terminal-only indicator with an explicitly joined worker.
use std::io::{IsTerminal, Write};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

pub struct Dots(Option<(mpsc::Sender<()>, JoinHandle<()>)>);
impl Dots {
    pub fn start(enabled: bool) -> Self {
        if !enabled || !std::io::stderr().is_terminal() || !std::io::stdout().is_terminal() {
            return Self(None);
        }
        let (stop, receiver) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut count = 0;
            while matches!(
                receiver.recv_timeout(Duration::from_millis(150)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                count = count % 12 + 1;
                let mut terminal = std::io::stderr().lock();
                if write!(terminal, "\r{:<12}", ".".repeat(count))
                    .and_then(|_| terminal.flush())
                    .is_err()
                {
                    break;
                }
            }
            let mut terminal = std::io::stderr().lock();
            write!(terminal, "\r            \r")
                .and_then(|_| terminal.flush())
                .ok();
        });
        Self(Some((stop, worker)))
    }
}
impl Drop for Dots {
    fn drop(&mut self) {
        if let Some((stop, worker)) = self.0.take() {
            let _ = stop.send(());
            let _ = worker.join();
        }
    }
}
