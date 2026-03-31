mod analysis;
mod cli;
mod commands;
mod core;
mod formats;

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::time::Instant;

use clap::Parser;
use rayon::ThreadPoolBuilder;

use crate::cli::help::{
    example_topic, is_help_request, is_version_request, preprocess_args, print_examples,
    print_usage, version_string,
};
use crate::cli::router::dispatch;
use crate::core::color::{enable_windows_ansi, is_terminal, Colors};
use crate::core::config::{Cli, Config};

fn main() {
    let started = Instant::now();
    let raw_args: Vec<String> = std::env::args().collect();

    if is_help_request(&raw_args) {
        print_usage();
        return;
    }
    if is_version_request(&raw_args) {
        println!("{}", version_string());
        return;
    }

    let cli = Cli::parse_from(preprocess_args(&raw_args));
    if cli.example {
        print_examples(example_topic(&raw_args, &cli));
        return;
    }

    let color = if cli.no_color {
        false
    } else if cli.force_color {
        true
    } else {
        enable_windows_ansi() && is_terminal()
    };

    let cfg = Config::from_cli(&cli, color);
    let c = Colors::new(color && !cfg.json);

    if cfg.workers > 0 {
        let _ = ThreadPoolBuilder::new()
            .num_threads(cfg.workers)
            .build_global();
    }

    let stdout = io::stdout();
    let mut stdout_lock = BufWriter::new(stdout.lock());
    let mut file_handle: Option<BufWriter<File>> = None;

    let w: &mut dyn Write = if !cfg.out_file.is_empty() {
        match File::create(&cfg.out_file) {
            Ok(f) => {
                file_handle = Some(BufWriter::new(f));
                file_handle.as_mut().unwrap()
            }
            Err(e) => {
                eprintln!(
                    "{}",
                    Colors::new(color).err_msg(&format!("Cannot open output file: {}", e))
                );
                std::process::exit(1);
            }
        }
    } else {
        &mut stdout_lock
    };

    if let Err(e) = dispatch(&raw_args, &cli, &cfg, w, &c) {
        eprintln!("{}", c.err_msg(&e));
        eprintln!("{}", c.dim("Run `resx help` for usage"));
        std::process::exit(1);
    }

    if !cfg.json {
        let elapsed = started.elapsed();
        let secs = elapsed.as_secs_f64();
        let pretty = if secs >= 60.0 {
            format!("{:.2}m", secs / 60.0)
        } else if secs >= 1.0 {
            format!("{:.2}s", secs)
        } else {
            format!("{}ms", elapsed.as_millis())
        };
        writeln!(w, "\n{}", c.dim(&format!("<completed in {}>", pretty))).ok();
    }

    if let Some(ref mut f) = file_handle {
        f.flush().ok();
    } else {
        stdout_lock.flush().ok();
    }
}
