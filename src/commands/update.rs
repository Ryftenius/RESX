use std::io::Write;
use std::path::Path;
use std::process::Command;

use crate::core::color::Colors;
use crate::core::config::Config;

pub fn run(cfg: &Config, w: &mut dyn Write, c: &Colors) -> Result<(), String> {
    let repo = Path::new(".");
    if !repo.join(".git").exists() {
        return Err("update requires a git checkout with a .git directory".to_owned());
    }

    let branch = run_git(["rev-parse", "--abbrev-ref", "HEAD"])?;
    let before = run_git(["rev-parse", "--short", "HEAD"])?;

    if !cfg.quiet {
        writeln!(
            w,
            "{}",
            c.info(&format!(
                "Repository: {}",
                std::env::current_dir()
                    .map_err(|e| e.to_string())?
                    .display()
            ))
        )
        .ok();
        writeln!(w, "{}", c.info(&format!("Branch: {}", branch.trim()))).ok();
        writeln!(
            w,
            "{}",
            c.info(&format!("Current commit: {}", before.trim()))
        )
        .ok();
    }

    let fetch = run_git_capture(["fetch", "--tags", "--prune", "origin"])?;
    if !fetch.status.success() {
        return Err(git_failure("git fetch", &fetch.stderr, &fetch.stdout));
    }

    let pull = run_git_capture(["pull", "--ff-only", "origin", branch.trim()])?;
    if !pull.status.success() {
        return Err(git_failure("git pull", &pull.stderr, &pull.stdout));
    }

    let after = run_git(["rev-parse", "--short", "HEAD"])?;
    let status = if before.trim() == after.trim() {
        "Already up to date"
    } else {
        "Updated successfully"
    };

    writeln!(w, "{}", c.ok(status)).ok();
    writeln!(
        w,
        "{}",
        c.dim(&format!("  {} -> {}", before.trim(), after.trim()))
    )
    .ok();
    Ok(())
}

fn run_git(args: [&str; 3]) -> Result<String, String> {
    let out = run_git_capture(args)?;
    if !out.status.success() {
        return Err(git_failure("git", &out.stderr, &out.stdout));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn run_git_capture<const N: usize>(args: [&str; N]) -> Result<std::process::Output, String> {
    Command::new("git")
        .args(args)
        .output()
        .map_err(|e| format!("spawn git: {}", e))
}

fn git_failure(step: &str, stderr: &[u8], stdout: &[u8]) -> String {
    let err = String::from_utf8_lossy(stderr).trim().to_owned();
    let out = String::from_utf8_lossy(stdout).trim().to_owned();
    if !err.is_empty() {
        format!("{} failed: {}", step, err)
    } else if !out.is_empty() {
        format!("{} failed: {}", step, out)
    } else {
        format!("{} failed", step)
    }
}
