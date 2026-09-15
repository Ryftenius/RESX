//! Bounded output collection for a task-owned external analyzer.
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

#[cfg(windows)]
pub fn capture(command: &mut Command, timeout: Duration, limit: usize) -> Result<Output, String> {
    use std::io::Read;
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn PeekNamedPipe(
            handle: *mut core::ffi::c_void,
            buffer: *mut core::ffi::c_void,
            size: u32,
            read: *mut u32,
            available: *mut u32,
            remaining: *mut u32,
        ) -> i32;
        fn WaitForSingleObject(handle: *mut core::ffi::c_void, milliseconds: u32) -> u32;
    }
    fn drain(
        pipe: &mut (impl Read + AsRawHandle),
        bytes: &mut Vec<u8>,
        remaining: &mut usize,
    ) -> Result<(), String> {
        let mut available = 0;
        // SAFETY: the pipe owns a live OS handle and `available` is a valid writable output.
        let okay = unsafe {
            PeekNamedPipe(
                pipe.as_raw_handle(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        };
        if okay == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(109) {
                return Ok(());
            }
            return Err(format!("Analyzer pipe query failed: {error}"));
        }
        if available as usize > *remaining {
            return Err("Analyzer output budget exceeded".into());
        }
        let mut chunk = [0u8; 8192];
        // Only consume bytes reported available; inherited descendant pipes
        // cannot keep a blocking read alive after this child exits.
        let mut amount = available as usize;
        while amount != 0 {
            let n = pipe
                .read(&mut chunk[..amount.min(8192)])
                .map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("Analyzer pipe ended during a reported read".into());
            }
            bytes.extend_from_slice(&chunk[..n]);
            amount -= n;
            *remaining -= n;
        }
        Ok(())
    }
    let mut child = command
        .creation_flags(0x08000000)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let started = Instant::now();
    let mut stdout = child.stdout.take().ok_or("Missing analyzer stdout")?;
    let mut stderr = child.stderr.take().ok_or("Missing analyzer stderr")?;
    let mut output = Vec::new();
    let mut errors = Vec::new();
    let mut remaining = limit;
    let result = (|| loop {
        drain(&mut stdout, &mut output, &mut remaining)?;
        drain(&mut stderr, &mut errors, &mut remaining)?;
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            drain(&mut stdout, &mut output, &mut remaining)?;
            drain(&mut stderr, &mut errors, &mut remaining)?;
            return Ok(Output {
                status,
                stdout: output,
                stderr: errors,
            });
        }
        if started.elapsed() >= timeout {
            return Err("Analyzer exceeded its wall-time budget".into());
        }
        // SAFETY: `child` owns the live process handle for the process launched above.
        if unsafe { WaitForSingleObject(child.as_raw_handle(), 20) } == u32::MAX {
            return Err(format!(
                "Analyzer wait failed: {}",
                std::io::Error::last_os_error()
            ));
        }
    })();
    if result.is_err() {
        // This Child handle identifies only the process launched above.
        let _ = child.kill();
        child
            .wait()
            .map_err(|e| format!("Analyzer cleanup failed: {e}"))?;
    }
    result
}

#[cfg(not(windows))]
pub fn capture(_: &mut Command, _: Duration, _: usize) -> Result<Output, String> {
    Err("Bounded external analyzer execution currently requires Windows".into())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    fn child() -> Command {
        Command::new(std::env::current_exe().unwrap())
    }
    #[test]
    fn process_fixture() {
        match std::env::var("RESX_PROCESS_TEST_MODE").as_deref() {
            Ok("flood") => {
                for _ in 0..512 {
                    println!("{}", "x".repeat(8192));
                }
            }
            Ok("sleep") => std::thread::sleep(Duration::from_secs(30)),
            _ => (),
        }
    }
    #[test]
    fn deadline_and_output_overflow_kill_owned_child() {
        for mode in ["flood", "sleep"] {
            let mut command = child();
            command
                .args([
                    "--exact",
                    "core::process::tests::process_fixture",
                    "--nocapture",
                ])
                .env("RESX_PROCESS_TEST_MODE", mode);
            let start = Instant::now();
            let error = capture(&mut command, Duration::from_millis(400), 16384).unwrap_err();
            assert!(
                error.contains(if mode == "flood" {
                    "output budget"
                } else {
                    "wall-time"
                }),
                "{error}"
            );
            assert!(start.elapsed() < Duration::from_secs(4));
        }
    }
}
