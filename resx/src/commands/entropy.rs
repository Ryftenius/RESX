use std::io::Write;

use crate::analysis::entropy::{analyze_entropy, EntropyWindow};
use crate::core::color::Colors;
use crate::core::config::Config;
use crate::core::json::versioned_object;
use crate::core::search::find_dll_path;
use crate::formats::pe::parse_pe;

pub fn run(dll_arg: &str, cfg: &Config, w: &mut dyn Write, c: &Colors) -> Result<(), String> {
    if dll_arg.is_empty() {
        return Err("Use `resx entropy <image>`".to_owned());
    }

    let path = find_dll_path(dll_arg, cfg)?;
    let image = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let raw = std::fs::read(&path).map_err(|e| format!("read file: {}", e))?;
    let pe = parse_pe(&raw).map_err(|e| e.0)?;
    let report = analyze_entropy(
        &image,
        &pe,
        &raw,
        cfg.entropy_window,
        cfg.entropy_stride,
        cfg.entropy_all,
    );

    if cfg.json {
        writeln!(
            w,
            "{}",
            serde_json::to_string_pretty(&versioned_object("entropy", &report)).unwrap_or_default()
        )
        .ok();
        return Ok(());
    }

    writeln!(
        w,
        "{}",
        c.bold(&format!(
            "Entropy map: {} ({}, window {}, stride {})",
            report.image, report.scope, report.window_size, report.stride
        ))
    )
    .ok();
    writeln!(
        w,
        "  avg {:.3}  min {:.3}  max {:.3}  high {}  low {}  zero-heavy {}  ascii-heavy {}",
        report.summary.avg_entropy,
        report.summary.min_entropy,
        report.summary.max_entropy,
        report.summary.high_entropy_windows,
        report.summary.low_entropy_windows,
        report.summary.zero_heavy_windows,
        report.summary.ascii_heavy_windows
    )
    .ok();

    if report.windows.is_empty() {
        writeln!(
            w,
            "{}",
            c.dim("No mapped windows found for the selected scope.")
        )
        .ok();
        return Ok(());
    }

    print_plot(w, c, &report.windows);
    writeln!(
        w,
        "\n{}",
        c.dim("RVA range             section    ent   ascii zero uniq flags")
    )
    .ok();
    for window in &report.windows {
        print_window(w, c, window);
    }

    Ok(())
}

fn print_window(w: &mut dyn Write, c: &Colors, window: &EntropyWindow) {
    let flags = if window.flags.is_empty() {
        c.dim("-")
    } else {
        window.flags.join(",")
    };
    let entropy = if window.entropy >= 7.15 {
        c.b_red(&format!("{:.3}", window.entropy))
    } else if window.entropy <= 2.0 {
        c.b_yellow(&format!("{:.3}", window.entropy))
    } else {
        format!("{:.3}", window.entropy)
    };
    writeln!(
        w,
        "{}-{}  {:<10} {}  {:>4.0}% {:>4.0}% {:>4.0}% {}",
        window.rva,
        window.end_rva,
        truncate(&window.section, 10),
        entropy,
        window.ascii_ratio * 100.0,
        window.zero_ratio * 100.0,
        window.unique_ratio * 100.0,
        flags
    )
    .ok();
}

fn print_plot(w: &mut dyn Write, c: &Colors, windows: &[EntropyWindow]) {
    let width = windows.len().clamp(24, 96);
    let height = 17usize;
    let mut canvas = vec![vec![' '; width]; height];

    let bins = aggregate(windows, width);
    for (x, bin) in bins.iter().enumerate() {
        plot_point(&mut canvas, x, bin.entropy, '*');
        plot_point(&mut canvas, x, bin.ascii_ratio * 8.0, 'a');
        plot_point(&mut canvas, x, bin.zero_ratio * 8.0, 'z');
        plot_point(&mut canvas, x, bin.unique_ratio * 8.0, 'u');
    }

    writeln!(
        w,
        "\n{}",
        c.bold("Entropy graph (* entropy, a ASCII, z zero, u unique)")
    )
    .ok();
    for (row, cells) in canvas.iter().enumerate().take(height) {
        let value = 8.0 - (row as f64 * 8.0 / (height - 1) as f64);
        let line = cells.iter().collect::<String>();
        writeln!(w, "{value:>4.1} |{line}|").ok();
    }
    writeln!(w, "     +{}+", "-".repeat(width)).ok();
    if let (Some(first), Some(last)) = (windows.first(), windows.last()) {
        writeln!(
            w,
            "      {}{}{}",
            first.rva,
            " ".repeat(width.saturating_sub(first.rva.len() + last.end_rva.len())),
            last.end_rva
        )
        .ok();
    }
}

#[derive(Debug, Clone, Copy)]
struct PlotBin {
    entropy: f64,
    ascii_ratio: f64,
    zero_ratio: f64,
    unique_ratio: f64,
}

fn aggregate(windows: &[EntropyWindow], width: usize) -> Vec<PlotBin> {
    let mut bins = Vec::with_capacity(width);
    for x in 0..width {
        let start = x * windows.len() / width;
        let end = ((x + 1) * windows.len() / width)
            .max(start + 1)
            .min(windows.len());
        let slice = &windows[start..end];
        let len = slice.len() as f64;
        bins.push(PlotBin {
            entropy: slice.iter().map(|w| w.entropy).sum::<f64>() / len,
            ascii_ratio: slice.iter().map(|w| w.ascii_ratio).sum::<f64>() / len,
            zero_ratio: slice.iter().map(|w| w.zero_ratio).sum::<f64>() / len,
            unique_ratio: slice.iter().map(|w| w.unique_ratio).sum::<f64>() / len,
        });
    }
    bins
}

fn plot_point(canvas: &mut [Vec<char>], x: usize, value: f64, ch: char) {
    let height = canvas.len();
    if height == 0 || canvas[0].is_empty() {
        return;
    }
    let y = ((8.0 - value.clamp(0.0, 8.0)) / 8.0 * (height - 1) as f64).round() as usize;
    let width = canvas[0].len();
    let y = y.min(height - 1);
    let x = x.min(width - 1);
    let slot = &mut canvas[y][x];
    *slot = if *slot == ' ' || *slot == ch { ch } else { '#' };
}

fn truncate(s: &str, width: usize) -> String {
    if s.len() <= width {
        s.to_owned()
    } else {
        s.chars().take(width.saturating_sub(1)).collect::<String>() + "~"
    }
}
