use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::time::Instant;

use rayon::ThreadPoolBuilder;

use resx::cli::help::{
    example_topic, help_topic, is_help_request, is_version_request, normalize_cli_syntax,
    preprocess_args, print_examples, print_usage, product_banner,
};
use resx::cli::router::dispatch;
use resx::core::color::{enable_windows_ansi, is_terminal, Colors};
use resx::core::config::{parse_cli, Config};
use resx::core::diagnostic::Severity;

fn main() {
    let started = Instant::now();
    let raw_args = normalize_cli_syntax(&std::env::args().collect::<Vec<_>>());

    if is_help_request(&raw_args) {
        if let Some(topic) = help_topic(&raw_args) {
            print_examples(topic);
        } else {
            print_usage();
        }
        return;
    }
    if is_version_request(&raw_args) {
        println!("{}", product_banner());
        return;
    }

    let cli = parse_cli(preprocess_args(&raw_args)).unwrap_or_else(|error| error.exit());
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

    resx::core::diagnostic::init(
        (cli.diagnostic || cli.diagnostic_trace) && !cli.quiet,
        cli.diagnostic_trace && !cli.quiet,
        color,
    );
    resx::diagnostic_event!(Severity::Info, "cli", "operation.start")
        .field(
            "command",
            raw_args.get(1).map(String::as_str).unwrap_or("dump"),
        )
        .field("argc", raw_args.len())
        .field("version", env!("CARGO_PKG_VERSION"))
        .field("commit", resx::core::diagnostic::BUILD_COMMIT)
        .field("binary_sha256", resx::core::diagnostic::binary_sha256())
        .field(
            "diagnostic_schema_version",
            resx::core::diagnostic::SCHEMA_VERSION,
        )
        .field(
            "diagnostic_level",
            if cli.diagnostic_trace {
                "TRACE"
            } else {
                "DEBUG"
            },
        )
        .emit("parsed command line and started operation");

    let cfg = Config::from_cli(&cli, color);
    let terminal_c = Colors::new(color && !cfg.json);
    let c = Colors::new(color && !cfg.json && cfg.out_file.is_empty());
    if cfg.workers > 0 {
        let _ = ThreadPoolBuilder::new()
            .num_threads(cfg.workers)
            .build_global();
    }

    let stdout = io::stdout();
    let mut stdout_lock = io::LineWriter::new(stdout.lock());
    let mut file_handle: Option<BufWriter<File>> = None;

    let w: &mut dyn Write = if !cfg.out_file.is_empty() {
        let evidence_output = raw_args.get(1).is_some_and(|arg| {
            matches!(
                arg.to_ascii_lowercase().as_str(),
                "payload" | "contracts" | "ipc" | "network" | "crypto" | "strings" | "yara"
            )
        });
        let opened = if evidence_output {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&cfg.out_file)
        } else {
            File::create(&cfg.out_file)
        };
        match opened {
            Ok(f) => {
                file_handle = Some(BufWriter::new(f));
                match file_handle.as_mut() {
                    Some(handle) => handle,
                    None => unreachable!("file handle was just initialized"),
                }
            }
            Err(e) => {
                eprintln!(
                    "{}",
                    terminal_c.err_msg(&format!("Cannot open output file: {}", e))
                );
                std::process::exit(1);
            }
        }
    } else {
        &mut stdout_lock
    };
    resx::core::table::configure(cfg.out_file.is_empty());

    if cfg.verbose && !cfg.quiet {
        eprintln!("{}", terminal_c.bold(&product_banner()));
        eprintln!(
            "{} command={} input={} json={} symbols_disabled={}",
            terminal_c.label("RESX:"),
            terminal_c.value(raw_args.get(1).map(String::as_str).unwrap_or("dump")),
            terminal_c.value(&format!("{:?}", cfg.dll)),
            terminal_c.value(&cfg.json.to_string()),
            terminal_c.value(&cfg.no_pdb.to_string())
        );
        eprintln!(
            "{} diagnostics use stderr; analysis output retains its original format",
            terminal_c.label("RESX:")
        );
    }

    let dispatch_started = Instant::now();
    if let Err(e) = dispatch(&raw_args, &cli, &cfg, w, &c) {
        resx::diagnostic_event!(Severity::Error, "cli.dispatch", "operation.failed")
            .field("duration_us", dispatch_started.elapsed().as_micros())
            .field("reason", &e)
            .emit("command dispatch failed");
        eprintln!("{}", terminal_c.err_msg(&e));
        eprintln!("{}", terminal_c.dim("Run `resx help` for usage"));
        std::process::exit(1);
    }
    resx::diagnostic_event!(Severity::Info, "cli.dispatch", "operation.complete")
        .field("duration_us", dispatch_started.elapsed().as_micros())
        .emit("command dispatch completed");
    if let Some(report) = cli.debug_report.as_deref() {
        let target = if cfg.dll.is_empty() {
            None
        } else {
            resx::core::search::find_dll_path(&cfg.dll, &cfg).ok()
        };
        if let Err(error) = resx::core::debug_report::write(
            std::path::Path::new(report),
            &raw_args,
            target.as_deref(),
            cli.debug_report_include_target,
            started.elapsed().as_millis(),
        ) {
            eprintln!("{}", terminal_c.err_msg(&format!("debug report: {error}")));
            std::process::exit(1);
        }
    }

    if let Some(ref mut f) = file_handle {
        f.flush().ok();
    } else {
        stdout_lock.flush().ok();
    }

    if cfg.time {
        let elapsed = started.elapsed();
        let secs = elapsed.as_secs_f64();
        let pretty = if secs >= 60.0 {
            format!("{:.2}m", secs / 60.0)
        } else if secs >= 1.0 {
            format!("{:.2}s", secs)
        } else {
            format!("{}ms", elapsed.as_millis())
        };
        let message = c.dim(&format!("RESX: completed in {}", pretty));
        if cfg.out_file.is_empty() {
            writeln!(stdout_lock, "{message}").ok();
            stdout_lock.flush().ok();
        } else {
            eprintln!("{message}");
        }
    }
}
