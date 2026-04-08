use std::io::Write;

use crate::core::color::Colors;
use crate::core::config::Config;

pub fn run(
    dll_arg: &str,
    func_arg: &str,
    cfg: &Config,
    w: &mut dyn Write,
    c: &Colors,
) -> Result<(), String> {
    let mut intelli_cfg = cfg.clone();
    intelli_cfg.intelli = true;
    crate::commands::dump::run(dll_arg, func_arg, &intelli_cfg, w, c)
}
