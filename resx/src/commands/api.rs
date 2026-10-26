use std::io::Write;

use crate::analysis::headers;
use crate::core::config::Config;

pub fn run(name: &str, cfg: &Config, w: &mut dyn Write) -> Result<(), String> {
    let dir = cfg.headers.as_deref().ok_or_else(|| {
        "Configure Windows SDK headers with `resx config --headers <directory>` first".to_owned()
    })?;
    let index = headers::load(std::path::Path::new(dir))?;
    let prototype = index
        .prototype(name)
        .ok_or_else(|| format!("No declaration for {name} in the configured SDK headers"))?;
    let declaration = index.declaration(prototype);
    if cfg.json {
        let value = crate::core::json::versioned_object(
            "api",
            serde_json::json!({
                "prototype": prototype, "declaration": declaration, "headers": index.root,
            }),
        );
        writeln!(
            w,
            "{}",
            serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?
        )
        .map_err(|e| e.to_string())?;
    } else {
        writeln!(w, "{declaration}").map_err(|e| e.to_string())?;
        for param in &prototype.params {
            let families = index.families(&prototype.name, &param.name);
            if !families.is_empty() {
                writeln!(w, "  {}: {}", param.name, families.join(", "))
                    .map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(())
}
