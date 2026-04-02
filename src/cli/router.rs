use std::io::Write;

use crate::commands;
use crate::core::color::Colors;
use crate::core::config::{Cli, Config};

pub fn dispatch(
    raw_args: &[String],
    cli: &Cli,
    cfg: &Config,
    w: &mut dyn Write,
    c: &Colors,
) -> Result<(), String> {
    let dll_arg = cfg.dll.clone();
    let func_arg = cfg.function.clone();
    let is_peinfo_shorthand = dll_arg.eq_ignore_ascii_case("peinfo") && !func_arg.is_empty();

    if cli.priority {
        return commands::priority::run(cfg, w, c);
    }

    if cli.update {
        return commands::update::run(cfg, w, c);
    }

    if cfg.explain {
        let term = if !func_arg.is_empty() {
            &func_arg
        } else {
            &dll_arg
        };
        if term.is_empty() {
            return Err("Specify a symbol or prefix to explain".to_owned());
        }
        return commands::explain::run(term, cfg, w, c);
    }

    if is_locate_mode(cfg, &dll_arg, &func_arg) {
        let name = if !func_arg.is_empty() {
            &func_arg
        } else {
            &dll_arg
        };
        if name.is_empty() {
            return Err("Specify a function name to locate".to_owned());
        }
        return commands::locate::run(name, cfg, w, c);
    }

    if is_peinfo_shorthand {
        return commands::peinfo::run(&func_arg, cfg, w, c);
    }
    if raw_args.len() >= 2 && raw_args[1].eq_ignore_ascii_case("cfg") {
        return commands::cfg::run(&dll_arg, &func_arg, cfg, w, c);
    }
    if raw_args.len() >= 2 && raw_args[1].eq_ignore_ascii_case("intelli") {
        return commands::intelli::run(&dll_arg, &func_arg, cfg, w, c);
    }
    if cfg.peinfo && !dll_arg.is_empty() && func_arg.is_empty() {
        return commands::peinfo::run(&dll_arg, cfg, w, c);
    }
    if cfg.follow_callers && !dll_arg.is_empty() && !func_arg.is_empty() {
        return commands::follow::run(&dll_arg, &func_arg, cfg, w, c);
    }
    if cfg.show_eat && func_arg.is_empty() && cfg.at_rva.is_empty() && cfg.ordinal == 0 {
        return commands::show_eat::run(&dll_arg, cfg, w, c);
    }
    if cfg.show_iat && func_arg.is_empty() && cfg.at_rva.is_empty() && cfg.ordinal == 0 {
        return commands::show_iat::run(&dll_arg, cfg, w, c);
    }
    if cfg.show_syms && func_arg.is_empty() && cfg.at_rva.is_empty() && cfg.ordinal == 0 {
        return commands::show_syms::run(&dll_arg, cfg, w, c);
    }
    if should_dump(cfg, &func_arg) {
        return commands::dump::run(&dll_arg, &func_arg, cfg, w, c);
    }
    if dll_arg.is_empty() {
        return Err(
            "Specify a command such as dump, cfg, intelli, peinfo, sections, eat, iat, syms, pechk, priority, callers, locate, locate-sym, yara, update, or help".to_owned(),
        );
    }

    Err(
        "Incomplete command. Use `resx dump <dll> <function>`, `resx callers <dll> <function>`, `resx locate <name>`, `resx priority`, `resx update`, or `resx help`".to_owned(),
    )
}

fn is_locate_mode(cfg: &Config, dll_arg: &str, func_arg: &str) -> bool {
    cfg.locate
        || cfg.locate_deep
        || (!dll_arg.is_empty()
            && !dll_arg.eq_ignore_ascii_case("peinfo")
            && func_arg.is_empty()
            && cfg.at_rva.is_empty()
            && cfg.ordinal == 0
            && !cfg.show_eat
            && !cfg.show_iat
            && !cfg.show_syms
            && !cfg.follow_callers
            && !cfg.peinfo
            && !cfg.sections
            && !cfg.pechk
            && !cfg.hookchk
            && !cfg.intelli
            && !cfg.explain
            && cfg.cfg_view.is_empty()
            && cfg.yara.is_empty())
}

fn should_dump(cfg: &Config, func_arg: &str) -> bool {
    !func_arg.is_empty()
        || !cfg.at_rva.is_empty()
        || cfg.ordinal > 0
        || cfg.show_eat
        || cfg.show_iat
        || cfg.sections
        || cfg.pechk
        || cfg.hookchk
        || cfg.intelli
        || !cfg.cfg_view.is_empty()
        || !cfg.yara.is_empty()
}
