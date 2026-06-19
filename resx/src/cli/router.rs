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

    if cli.resx_scan {
        return commands::scan::run(cli, w);
    }

    if cfg.resx_diff {
        if dll_arg.is_empty() || func_arg.is_empty() {
            return Err("Use `resx diff <image-a> <image-b> [image-c ...]`".to_owned());
        }
        return commands::diff::run(&dll_arg, &func_arg, cfg, w, c);
    }

    if cfg.patch || (raw_args.len() >= 2 && raw_args[1].eq_ignore_ascii_case("patch")) {
        return commands::patch::run(&dll_arg, &func_arg, cfg, w, c);
    }

    if !cfg.extra_diff_images.is_empty() {
        return Err(unexpected_extra_positional_error(
            raw_args,
            &dll_arg,
            &func_arg,
            &cfg.extra_diff_images[0],
        ));
    }

    if cfg.resx_index {
        if dll_arg.is_empty() {
            return Err("Use `resx index <dir-or-image> --db <file>`".to_owned());
        }
        return commands::index::run(&dll_arg, cfg, w, c);
    }

    if cfg.resx_hunt {
        if dll_arg.is_empty() {
            return Err("Use `resx hunt <sample> --db <file>`".to_owned());
        }
        return commands::hunt::run(&dll_arg, cfg, w, c);
    }

    if cfg.reconstruct_cfg {
        return commands::reconstruct_cfg::run(&dll_arg, cfg, w, c);
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

    if raw_args.len() >= 2 && raw_args[1].eq_ignore_ascii_case("types") {
        let dll = &dll_arg;
        let query = &func_arg;
        if dll.is_empty() {
            return Err("Use `resx types <dll> [query]`".to_owned());
        }
        return commands::types::run(dll, query, cfg, w, c);
    }

    if raw_args.len() >= 2 && raw_args[1].eq_ignore_ascii_case("dump") {
        if dll_arg.is_empty() {
            return Err("Use `resx dump <image> [function|--at <addr>|--ordinal <n>]`".to_owned());
        }
        return commands::dump::run(&dll_arg, &func_arg, cfg, w, c);
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
    if raw_args.len() >= 2 && raw_args[1].eq_ignore_ascii_case("behavior") {
        return commands::behavior::run(&dll_arg, cfg, w, c);
    }
    if raw_args.len() >= 2 && raw_args[1].eq_ignore_ascii_case("unpack") {
        return commands::unpack::run(&dll_arg, cfg, w, c);
    }
    if raw_args.len() >= 2 && raw_args[1].eq_ignore_ascii_case("entropy") {
        return commands::entropy::run(&dll_arg, cfg, w, c);
    }
    if cfg.peinfo && !dll_arg.is_empty() && func_arg.is_empty() {
        return commands::peinfo::run(&dll_arg, cfg, w, c);
    }
    if cfg.behavior && !dll_arg.is_empty() && func_arg.is_empty() {
        return commands::behavior::run(&dll_arg, cfg, w, c);
    }
    if cfg.unpack && !dll_arg.is_empty() && func_arg.is_empty() {
        return commands::unpack::run(&dll_arg, cfg, w, c);
    }
    if cfg.entropy && !dll_arg.is_empty() && func_arg.is_empty() {
        return commands::entropy::run(&dll_arg, cfg, w, c);
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
            "Specify a command such as dump, cfg, reconstruct-cfg, intelli, behavior, unpack, entropy, types, peinfo, sections, eat, iat, syms, pechk, priority, callers, locate, locate-sym, scan, yara, update, or help".to_owned(),
        );
    }

    Err(
        "Incomplete command. Use `resx dump <dll> <function>`, `resx unpack <dll>`, `resx entropy <dll>`, `resx reconstruct-cfg <dll>`, `resx callers <dll> <function>`, `resx scan <path>`, `resx locate <name>`, `resx priority`, `resx update`, or `resx help`".to_owned(),
    )
}

fn unexpected_extra_positional_error(
    raw_args: &[String],
    first: &str,
    second: &str,
    extra: &str,
) -> String {
    let command = raw_args.get(1).map(String::as_str).unwrap_or_default();
    let command_hint = match command.to_ascii_lowercase().as_str() {
        "xref" => "\n  Did you mean `resx xrefs <image> <symbol>`?",
        "ref" | "refs" => {
            "\n  Did you mean `resx refs <image> <symbol>` or `resx xrefs <image> <symbol>`?"
        }
        "call" | "caller" => "\n  Did you mean `resx callers <image> <symbol>`?",
        _ => "",
    };

    format!(
        "ECLI001: unexpected extra positional argument `{extra}`\n  Parsed positional inputs as: image=`{first}`, target=`{second}`, extra=`{extra}`\n  RESX accepts multiple image positionals only with `resx diff <image-a> <image-b> [image-c ...]`.\n  Common forms:\n    resx dump <image> <symbol> --xrefs\n    resx xrefs <image> <symbol>\n    resx callers <image> <symbol>{command_hint}"
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
            && !cfg.behavior
            && !cfg.unpack
            && !cfg.entropy
            && !cfg.patch
            && !cfg.reconstruct_cfg
            && !cfg.resx_diff
            && !cfg.resx_index
            && !cfg.resx_hunt
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
        || cfg.behavior
        || cfg.unpack
        || cfg.entropy
        || cfg.patch
        || cfg.reconstruct_cfg
        || cfg.resx_diff
        || cfg.resx_index
        || cfg.resx_hunt
        || !cfg.cfg_view.is_empty()
        || !cfg.yara.is_empty()
}
