//! Pad plain text before applying terminal styling. Escape untrusted control text.
use super::color::Colors;
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};

const FALLBACK_OUTPUT_WIDTH: usize = 120;
const MIN_COLUMN_WIDTH: usize = 8;
const FIXED_COLUMN_WIDTH: usize = 16;
const SOFT_COLUMN_WIDTH: usize = 48;
static OUTPUT_WIDTH: AtomicUsize = AtomicUsize::new(FALLBACK_OUTPUT_WIDTH);

pub fn configure(use_terminal_width: bool) {
    let width = if use_terminal_width {
        terminal_width().unwrap_or(FALLBACK_OUTPUT_WIDTH)
    } else {
        FALLBACK_OUTPUT_WIDTH
    };
    OUTPUT_WIDTH.store(width.clamp(40, 512), Ordering::Relaxed);
}

fn wrap_cell(text: &str, width: usize) -> Vec<String> {
    if text.is_empty() {
        return vec![String::new()];
    }

    let width = width.max(1);
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= width {
        return vec![text.to_owned()];
    }

    let mut lines = Vec::new();
    let mut start = 0usize;
    while start < chars.len() {
        let remaining = chars.len() - start;
        if remaining <= width {
            lines.push(chars[start..].iter().collect());
            break;
        }

        let end = start + width;
        let split = chars[start..end]
            .iter()
            .rposition(|ch| ch.is_whitespace())
            .map(|position| start + position)
            .filter(|position| *position > start)
            .unwrap_or(end);
        let line: String = chars[start..split].iter().collect();
        lines.push(line.trim_end().to_owned());
        start = split;
        while start < chars.len() && chars[start].is_whitespace() {
            start += 1;
        }
    }
    lines
}

pub fn print(w: &mut dyn Write, headers: &[&str], rows: &[Vec<String>], c: &Colors) {
    if rows.is_empty() || headers.is_empty() {
        return;
    }

    // Preserve normal Unicode characters while escaping control characters.
    let clean = |s: &str| {
        let mut text = String::with_capacity(s.len());

        for ch in s.chars() {
            if ch.is_control() {
                text.extend(ch.escape_default());
            } else {
                text.push(ch);
            }
        }

        text
    };

    // Unicode-safe character count.
    //
    // This counts Unicode scalar values rather than UTF-8 bytes, preventing
    // multibyte characters from breaking width calculations.
    let char_width = |s: &str| s.chars().count();

    let mut effective_headers: Vec<&str> = headers.to_vec();
    let mut source_rows: Vec<Vec<String>> = rows.to_vec();
    let output_width = OUTPUT_WIDTH.load(Ordering::Relaxed);

    // Preserve the existing Field/Value two-column packing behavior.
    if headers == ["Field", "Value"]
        && output_width >= 108
        && rows.len() > 1
        && rows.iter().all(|row| row.len() <= 2)
    {
        effective_headers = vec!["Field", "Value", "Field", "Value"];

        source_rows = rows
            .chunks(2)
            .map(|pair| {
                let mut row = pair[0].clone();
                row.resize(2, String::new());

                if let Some(right) = pair.get(1) {
                    row.extend(right.iter().cloned());
                }

                row.resize(4, String::new());
                row
            })
            .collect();
    }

    let headers = effective_headers.as_slice();

    let data: Vec<Vec<String>> = source_rows
        .iter()
        .map(|row| {
            (0..headers.len())
                .map(|i| clean(row.get(i).map(String::as_str).unwrap_or("")))
                .collect()
        })
        .collect();

    // Calculate natural column widths using Unicode character counts
    // instead of UTF-8 byte lengths.
    let natural: Vec<usize> = headers
        .iter()
        .enumerate()
        .map(|(i, header)| {
            data.iter()
                .map(|row| char_width(&row[i]))
                .max()
                .unwrap_or(0)
                .max(char_width(header))
                .max(1)
        })
        .collect();

    let widths = allocate_widths(&natural, headers, output_width);

    // Build Unicode box-drawing borders.
    let make_border = |left: char, middle: char, right: char, horizontal: char| -> String {
        let sections = widths
            .iter()
            .map(|width| horizontal.to_string().repeat(width + 2))
            .collect::<Vec<_>>();

        format!("{}{}{}", left, sections.join(&middle.to_string()), right)
    };

    let top_border = make_border('┌', '┬', '┐', '─');
    let middle_border = make_border('├', '┼', '┤', '─');
    let bottom_border = make_border('└', '┴', '┘', '─');

    // Top border.
    writeln!(w, "{top_border}").ok();

    // Header row.
    let heading_cells: Vec<String> = headers
        .iter()
        .zip(&widths)
        .map(|(header, width)| {
            let current = char_width(header);
            let padding = width.saturating_sub(current);

            format!("{}{}", header, " ".repeat(padding))
        })
        .collect();

    let heading = format!("│ {} │", heading_cells.join(" │ "));

    writeln!(w, "{}", c.bold(&heading)).ok();

    // Separator between header and data.
    writeln!(w, "{middle_border}").ok();

    for row in data {
        let wrapped: Vec<Vec<String>> = row
            .iter()
            .zip(&widths)
            .map(|(text, width)| wrap_cell(text, *width))
            .collect();

        let height = wrapped.iter().map(Vec::len).max().unwrap_or(1);

        for line in 0..height {
            let cells: Vec<String> = wrapped
                .iter()
                .zip(&widths)
                .enumerate()
                .map(|(index, (lines, width))| {
                    let text = lines.get(line).map(String::as_str).unwrap_or("");

                    let current = char_width(text);
                    let padding = width.saturating_sub(current);

                    let padded = format!("{}{}", text, " ".repeat(padding));

                    // Preserve entropy highlighting.
                    if line == 0 && headers[index].eq_ignore_ascii_case("entropy") {
                        match text.parse::<f64>() {
                            Ok(value) if value >= 7.2 => c.b_red(&padded),
                            Ok(value) if value >= 6.5 => c.b_yellow(&padded),
                            _ => padded,
                        }
                    } else {
                        padded
                    }
                })
                .collect();

            writeln!(w, "│ {} │", cells.join(" │ ")).ok();
        }
    }

    // Bottom border.
    writeln!(w, "{bottom_border}").ok();
}

fn allocate_widths(natural: &[usize], headers: &[&str], output_width: usize) -> Vec<usize> {
    let border_cost = natural.len().saturating_mul(3).saturating_add(1);
    let budget = output_width.saturating_sub(border_cost).max(natural.len());
    let mut widths: Vec<_> = natural
        .iter()
        .zip(headers)
        .map(|(natural, header)| (*natural).min(header.len().max(MIN_COLUMN_WIDTH)).max(1))
        .collect();
    shrink_to_budget(&mut widths, budget);
    let mut spare = budget.saturating_sub(widths.iter().sum());

    while spare != 0 {
        let Some(index) = (0..widths.len())
            .filter(|index| {
                natural[*index] <= FIXED_COLUMN_WIDTH && widths[*index] < natural[*index]
            })
            .max_by_key(|index| natural[*index] - widths[*index])
        else {
            break;
        };
        widths[index] += 1;
        spare -= 1;
    }

    while spare != 0 {
        let next = (0..widths.len())
            .filter(|index| widths[*index] < natural[*index].min(SOFT_COLUMN_WIDTH))
            .max_by(|left, right| {
                let left_target = natural[*left].clamp(1, SOFT_COLUMN_WIDTH);
                let right_target = natural[*right].clamp(1, SOFT_COLUMN_WIDTH);
                let left_gap = (left_target - widths[*left]) * right_target;
                let right_gap = (right_target - widths[*right]) * left_target;
                left_gap.cmp(&right_gap)
            });
        let Some(index) = next else { break };
        widths[index] += 1;
        spare -= 1;
    }
    while spare != 0 {
        let Some(index) = (0..widths.len())
            .filter(|index| widths[*index] < natural[*index])
            .max_by_key(|index| natural[*index] - widths[*index])
        else {
            break;
        };
        widths[index] += 1;
        spare -= 1;
    }
    let mut expandable: Vec<usize> = headers
        .iter()
        .enumerate()
        .filter_map(|(index, header)| {
            matches!(
                header.to_ascii_lowercase().as_str(),
                "value" | "apis" | "references" | "details" | "notes" | "instruction"
            )
            .then_some(index)
        })
        .collect();
    if expandable.is_empty() {
        expandable = (0..headers.len()).collect();
    }
    let mut cursor = 0usize;
    while spare != 0 && !expandable.is_empty() {
        widths[expandable[cursor % expandable.len()]] += 1;
        cursor += 1;
        spare -= 1;
    }
    widths
}

fn shrink_to_budget(widths: &mut [usize], budget: usize) {
    while widths.iter().sum::<usize>() > budget {
        let Some(index) = (0..widths.len())
            .filter(|index| widths[*index] > 1)
            .max_by_key(|index| widths[*index])
        else {
            break;
        };
        widths[index] -= 1;
    }
}

#[cfg(windows)]
fn terminal_width() -> Option<usize> {
    use std::ffi::c_void;

    #[repr(C)]
    struct Coord {
        x: i16,
        y: i16,
    }
    #[repr(C)]
    struct SmallRect {
        left: i16,
        top: i16,
        right: i16,
        bottom: i16,
    }
    #[repr(C)]
    struct ConsoleScreenBufferInfo {
        size: Coord,
        cursor_position: Coord,
        attributes: u16,
        window: SmallRect,
        maximum_window_size: Coord,
    }
    #[link(name = "Kernel32")]
    unsafe extern "system" {
        fn GetStdHandle(std_handle: u32) -> *mut c_void;
        fn GetConsoleScreenBufferInfo(
            console_output: *mut c_void,
            info: *mut ConsoleScreenBufferInfo,
        ) -> i32;
    }
    let mut info = std::mem::MaybeUninit::<ConsoleScreenBufferInfo>::uninit();
    // SAFETY: GetStdHandle takes a constant selector and returns an opaque handle.
    let handle = unsafe { GetStdHandle(-11i32 as u32) };
    if handle.is_null() || handle == (-1isize as *mut c_void) {
        return None;
    }
    // SAFETY: the handle was checked and `info` points to writable storage of the declared C layout.
    if unsafe { GetConsoleScreenBufferInfo(handle, info.as_mut_ptr()) } == 0 {
        return None;
    }
    // SAFETY: the successful Win32 call initialized the complete structure.
    let info = unsafe { info.assume_init() };
    usize::try_from(i32::from(info.window.right) - i32::from(info.window.left) + 1).ok()
}

#[cfg(not(windows))]
fn terminal_width() -> Option<usize> {
    std::env::var("COLUMNS").ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::{allocate_widths, wrap_cell};

    #[test]
    fn wraps_words_before_hard_splitting_tokens() {
        assert_eq!(
            wrap_cell("alpha beta gamma", 10),
            vec!["alpha", "beta gamma"]
        );
        assert_eq!(wrap_cell("abcdefghijkl", 5), vec!["abcde", "fghij", "kl"]);
    }

    #[test]
    fn wide_terminals_give_long_columns_the_available_space() {
        let widths = allocate_widths(&[35, 14, 500], &["Capability", "Confidence", "APIs"], 250);
        assert_eq!(widths.iter().sum::<usize>() + 10, 250);
        assert_eq!(widths[0], 35);
        assert_eq!(widths[1], 14);
        assert!(widths[2] > 180);
    }

    #[test]
    fn narrow_terminals_remain_bounded() {
        let widths = allocate_widths(&[35, 14, 500], &["Capability", "Confidence", "APIs"], 80);
        assert!(widths.iter().sum::<usize>() + 10 <= 80);
        assert!(widths.iter().all(|width| *width > 0));
        let many = allocate_widths(&[20; 7], &["Header"; 7], 40);
        assert!(many.iter().sum::<usize>() + 22 <= 40);
        let evidence = allocate_widths(
            &[6, 45, 10, 12, 24],
            &["Vendor", "Capability", "RVA", "Owner", "Instruction"],
            80,
        );
        assert_eq!(evidence[2], 10);
        assert_eq!(evidence[3], 12);
    }
}
