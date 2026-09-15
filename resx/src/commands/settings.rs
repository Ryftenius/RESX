use crate::core::color::Colors;
use crate::core::config::Cli;
use crate::core::preferences::{validate_macro, validate_style, Preferences, REGISTRY_PATH};
use std::io::Write;

pub fn run(cli: &Cli, output: &mut dyn Write, colors: &Colors) -> Result<(), String> {
    let mut preferences = Preferences::load();
    if let Some(style) = &cli.command_style {
        validate_style(style)?;
        preferences.command_style = style.to_ascii_lowercase();
    }
    if let Some(name) = &cli.entry_macro {
        validate_macro(name)?;
        preferences.entry_macro = name.clone();
    }
    if let Some(name) = &cli.rentry_macro {
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
            vec!["Command style".into(), preferences.command_style],
            vec!["Entry macro".into(), preferences.entry_macro],
            vec!["Real-entry macro".into(), preferences.rentry_macro],
            vec![
                "Saved invoke profiles".into(),
                preferences.invoke_profiles.len().to_string(),
            ],
        ],
        colors,
    );
    Ok(())
}
