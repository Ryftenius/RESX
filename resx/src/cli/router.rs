use std::io::Write;

use crate::cli::args::Command;
use crate::commands;
use crate::core::color::Colors;
use crate::core::config::{Config, Options};

pub fn dispatch(
    command: &Command,
    options: &Options,
    cfg: &Config,
    w: &mut dyn Write,
    c: &Colors,
) -> Result<(), String> {
    let image = cfg.dll.as_str();
    let target = cfg.function.as_str();
    match command {
        Command::Api(args) => commands::api::run(&args.name, cfg, w),
        Command::Peinfo(_) => commands::peinfo::run(image, cfg, w, c),
        Command::Sections(_) => commands::dump::run(image, "", cfg, w, c),
        Command::Pechk(_) => commands::pechk::run(image, cfg, w, c),
        Command::Eat(_) => commands::show_eat::run(image, cfg, w, c),
        Command::Iat(_) => commands::show_iat::run(image, cfg, w, c),
        Command::Syms(_) => commands::show_syms::run(image, cfg, w, c),
        Command::Types(_) => commands::types::run(image, target, cfg, w, c),

        Command::Dump(_) | Command::Calls(_) | Command::Xrefs(_) => {
            commands::dump::run(image, target, cfg, w, c)
        }
        // The cfg view renders text only; with --json the dump document carries the
        // same graph (`cfg`) and its recovered structure.
        Command::Cfg(_) if cfg.json => commands::dump::run(image, target, cfg, w, c),
        Command::Cfg(_) => commands::cfg::run(image, target, cfg, w, c),
        Command::ReconstructCfg(_) => commands::reconstruct_cfg::run(image, cfg, w, c),
        Command::Callers(_) => commands::follow::run(image, target, cfg, w, c),
        Command::Intelli(_) => commands::intelli::run(image, target, cfg, w, c),
        Command::Behavior(_) => commands::behavior::run(image, cfg, w, c),

        Command::Contracts(_)
        | Command::Ipc(_)
        | Command::Network(_)
        | Command::Crypto(_)
        | Command::Strings(_) => commands::contracts::run(cfg, command.name(), w),
        Command::Driver(_) => commands::driver::run(cfg, false, w, c),
        Command::Ioctl(_) => commands::driver::run(cfg, true, w, c),
        Command::Entropy(_) => commands::entropy::run(image, cfg, w, c),

        Command::Yara(_) => commands::yara::run(image, cfg, w, c),
        Command::Find(_) => commands::find::run(image, cfg, w, c),
        Command::Scan(_) => commands::scan::run(options, w),
        Command::Diff(_) => commands::diff::run(image, target, cfg, w, c),
        Command::Index(_) => commands::index::run(image, cfg, w, c),
        Command::Hunt(_) => commands::hunt::run(image, cfg, w, c),
        Command::Locate(_) | Command::LocateSym(_) => commands::locate::run(image, cfg, w, c),

        Command::Payload(_) => commands::payload::run(options, cfg, w),
        Command::Patch(_) => commands::patch::run(image, "", cfg, w, c),

        Command::Priority => commands::priority::run(cfg, w, c),
        Command::Config(_) => commands::settings::run(options, w, c),
        Command::Update => commands::update::run(cfg, w, c),

        Command::Implicit(_) => dispatch_implicit(cfg, w, c),
    }
}

/// `resx <image> <target>` dumps; `resx <name>` with nothing to dump locates it; a
/// bare table flag shows that table, as in releases before subcommands.
fn dispatch_implicit(cfg: &Config, w: &mut dyn Write, c: &Colors) -> Result<(), String> {
    let image = cfg.dll.as_str();
    let target = cfg.function.as_str();
    let has_target = !target.is_empty() || !cfg.at_rva.is_empty() || cfg.ordinal > 0;
    if !has_target {
        if cfg.show_eat {
            return commands::show_eat::run(image, cfg, w, c);
        }
        if cfg.show_iat {
            return commands::show_iat::run(image, cfg, w, c);
        }
        if cfg.show_syms {
            return commands::show_syms::run(image, cfg, w, c);
        }
        let dumps_image = cfg.sections
            || cfg.pechk
            || cfg.hookchk
            || cfg.intelli
            || !cfg.cfg_view.is_empty()
            || !cfg.yara.is_empty();
        if !dumps_image {
            return commands::locate::run(image, cfg, w, c);
        }
    }
    commands::dump::run(image, target, cfg, w, c)
}
