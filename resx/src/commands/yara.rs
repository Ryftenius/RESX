use crate::analysis::yara::scan_file;
use crate::core::{
    color::Colors, config::Config, hash::sha256, json::versioned_object, search::find_dll_path,
};
use crate::presentation::output::print_yara_matches;
use serde_json::json;
use std::io::Write;

pub fn run(
    image: &str,
    cfg: &Config,
    output: &mut dyn Write,
    colors: &Colors,
) -> Result<(), String> {
    if image.is_empty() || cfg.yara.is_empty() {
        return Err("Use `resx yara <image> <rule.yar>`".into());
    }
    let path = find_dll_path(image, cfg)?;
    let raw = crate::core::input::read_image(&path).map_err(|error| error.to_string())?;
    let matches = scan_file(&path.to_string_lossy(), &cfg.yara)?;

    if cfg.json {
        let report = json!({
            "image": path,
            "image_sha256": sha256(&raw)?,
            "rule_inputs": cfg.yara,
            "match_count": matches.len(),
            "matches": matches,
        });
        serde_json::to_writer_pretty(&mut *output, &versioned_object("yara", report))
            .map_err(|error| error.to_string())?;
        writeln!(output).map_err(|error| error.to_string())?;
    } else {
        print_yara_matches(output, &matches, colors);
    }
    Ok(())
}
