use std::io::Write;

use crate::core::color::Colors;
use crate::core::config::Config;
use crate::core::priority::open_priority_file;

pub fn run(_cfg: &Config, w: &mut dyn Write, c: &Colors) -> Result<(), String> {
    let path = open_priority_file()?;
    writeln!(
        w,
        "{}",
        c.ok(&format!("Opened priority config: {}", path.display()))
    )
    .ok();
    Ok(())
}
