use crate::core::color::Colors;
use crate::core::config::Options;
use crate::core::preferences::{validate_macro, validate_style, Preferences, REGISTRY_PATH};
use std::io::Write;

pub fn run(options: &Options, output: &mut dyn Write, colors: &Colors) -> Result<(), String> {
    let mut preferences = Preferences::load();
    apply_limits(&mut preferences, options);
    if let Some(dir) = &options.headers {
        preferences.headers = if dir.eq_ignore_ascii_case("off") {
            None
        } else {
            let root = crate::providers::headers::resolve_root(std::path::Path::new(dir))
                .ok_or_else(|| {
                    format!("{dir} has no um/windows.h; specify a Windows SDK Include directory")
                })?;
            // Preferences outlive this working directory.
            let root = std::fs::canonicalize(root).map_err(|error| error.to_string())?;
            Some(root.to_string_lossy().into_owned())
        };
    }
    if let Some(style) = &options.command_style {
        validate_style(style)?;
        preferences.command_style = style.to_ascii_lowercase();
    }
    if let Some(name) = &options.entry_macro {
        validate_macro(name)?;
        preferences.entry_macro = name.clone();
    }
    if let Some(name) = &options.rentry_macro {
        validate_macro(name)?;
        preferences.rentry_macro = name.clone();
    }
    preferences.save()?;

    writeln!(output, "{}", colors.bold("RESX preferences")).ok();
    crate::core::table::print(
        output,
        &["Setting", "Value"],
        &[
            vec!["Registry".into(), format!("HKCU\\{REGISTRY_PATH}")],
            vec![
                "Windows SDK headers".into(),
                preferences.headers.unwrap_or_else(|| "off".into()),
            ],
            vec!["Command style".into(), preferences.command_style],
            vec!["Entry macro".into(), preferences.entry_macro],
            vec!["Real-entry macro".into(), preferences.rentry_macro],
            vec![
                "Instruction budget".into(),
                preferences
                    .max_insns
                    .map(|value| {
                        if value == 0 {
                            "unlimited".to_owned()
                        } else {
                            value.to_string()
                        }
                    })
                    .unwrap_or_else(|| "whole known function; otherwise 500".to_owned()),
            ],
            vec![
                "Traversal budget".into(),
                preferences
                    .max_total
                    .map(|value| {
                        if value == 0 {
                            "unlimited".to_owned()
                        } else {
                            value.to_string()
                        }
                    })
                    .unwrap_or_else(|| "500".to_owned()),
            ],
            vec![
                "String result limit".into(),
                preferences
                    .strings_limit
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "2048".to_owned()),
            ],
            vec![
                "String scan size (MiB)".into(),
                preferences
                    .strings_scan_mb
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "32".to_owned()),
            ],
            vec![
                "Saved invoke profiles".into(),
                preferences.invoke_profiles.len().to_string(),
            ],
        ],
        colors,
    );
    Ok(())
}

fn apply_limits(preferences: &mut Preferences, options: &Options) {
    if options.reset_limits {
        preferences.max_insns = None;
        preferences.max_total = None;
        preferences.strings_limit = None;
        preferences.strings_scan_mb = None;
    }
    if let Some(value) = options.saved_max_insns {
        preferences.max_insns = Some(value);
    }
    if let Some(value) = options.saved_max_total {
        preferences.max_total = Some(value);
    }
    if let Some(value) = options.saved_strings_limit {
        preferences.strings_limit = Some(value);
    }
    if let Some(value) = options.saved_strings_scan_mb {
        preferences.strings_scan_mb = Some(value);
    }
}

#[cfg(test)]
mod tests {
    use super::apply_limits;
    use crate::core::config::Options;
    use crate::core::preferences::Preferences;

    #[test]
    fn saved_limits_change_and_reset_without_touching_other_preferences() {
        let mut preferences = Preferences {
            command_style: "slash".to_owned(),
            ..Preferences::default()
        };
        let options = Options {
            saved_max_insns: Some(1200),
            saved_max_total: Some(900),
            saved_strings_limit: Some(4096),
            saved_strings_scan_mb: Some(64),
            ..Options::default()
        };
        apply_limits(&mut preferences, &options);
        assert_eq!(preferences.max_insns, Some(1200));
        assert_eq!(preferences.max_total, Some(900));
        assert_eq!(preferences.strings_limit, Some(4096));
        assert_eq!(preferences.strings_scan_mb, Some(64));

        apply_limits(
            &mut preferences,
            &Options {
                reset_limits: true,
                ..Options::default()
            },
        );
        assert!(preferences.max_insns.is_none());
        assert!(preferences.max_total.is_none());
        assert!(preferences.strings_limit.is_none());
        assert!(preferences.strings_scan_mb.is_none());
        assert_eq!(preferences.command_style, "slash");
    }
}
