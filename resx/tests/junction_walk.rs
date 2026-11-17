#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        for name in ["loop", "loop2"] {
            let _ = std::fs::remove_dir(self.0.join(name));
        }
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run_bounded(args: &[&Path]) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_resx"));
    for arg in args {
        command.arg(arg);
    }
    let mut child = command
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start RESX");
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("poll RESX") {
            assert!(status.success(), "RESX exited with {status}");
            return;
        }
        if started.elapsed() >= Duration::from_secs(5) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("RESX failed to finish a two-junction directory walk");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn scan_and_index_skip_parent_junctions() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root =
        std::env::temp_dir().join(format!("resx-junction-walk-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&root).expect("create fixture directory");
    let fixture = Fixture(root);

    for name in ["loop", "loop2"] {
        let status = Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(fixture.0.join(name))
            .arg(&fixture.0)
            .stdout(Stdio::null())
            .status()
            .expect("create directory junction");
        assert!(status.success(), "mklink /J failed with {status}");
    }

    let max_files = Path::new("1");
    run_bounded(&[
        Path::new("scan"),
        &fixture.0,
        Path::new("--max-files"),
        max_files,
    ]);

    let db = fixture.0.join("index.json");
    run_bounded(&[
        Path::new("index"),
        &fixture.0,
        Path::new("--max-files"),
        max_files,
        Path::new("--db"),
        &db,
    ]);
    assert!(db.is_file(), "index command did not write the corpus");
}
