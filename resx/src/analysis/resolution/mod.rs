//! Dynamic API resolution: APIs an image finds at run time instead of importing,
//! which ones, and how.
//!
//! Every function is interpreted symbolically (see [`machine`]) to find resolver
//! calls and what flows into them: GetProcAddress with a literal, stack-built or
//! decoded name; walks of the PEB loader lists; hand-parsed export and import tables;
//! and the hash constants such walkers compare against. Functions that resolve on
//! behalf of their callers are summarized, and the image is re-interpreted until those
//! summaries and the global API tables they fill stop changing. The result labels the
//! indirect calls made through resolved pointers and grades the techniques used, from
//! a plain GetProcAddress lookup to hashed lookups through the loader lists.

mod dictionary;
mod hashes;
mod image;
mod machine;
mod strings;

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};
use serde::{Serialize, Serializer};

use crate::formats::pe::{read_imports, read_load_config, PeFile};
use machine::{Context, Facts, Module, Name, ResId, Summary, Through, Val, Via};
use strings::How;

/// Re-interpretation rounds after the first pass; each round only revisits functions
/// whose callees or global tables changed.
const MAX_ROUNDS: usize = 6;
const MAX_EVIDENCE: usize = 32;

#[derive(Debug, Clone, Default, Serialize)]
pub struct ResolutionReport {
    /// One line naming the techniques found, most suspicious first; empty when none.
    pub summary: String,
    pub techniques: Vec<Technique>,
    pub resolved: Vec<ResolvedApi>,
    #[serde(skip)]
    targets: HashMap<u32, usize>,
    #[serde(skip)]
    resolvers: HashMap<u32, usize>,
}

impl ResolutionReport {
    /// The API called by the indirect call or jump at `rva`.
    pub fn call_target(&self, rva: u32) -> Option<&ResolvedApi> {
        self.targets.get(&rva).map(|&i| &self.resolved[i])
    }

    /// The API the resolver call at `rva` produces.
    pub fn resolver_call(&self, rva: u32) -> Option<&ResolvedApi> {
        self.resolvers.get(&rva).map(|&i| &self.resolved[i])
    }

    pub fn call_sites(&self) -> impl Iterator<Item = (u32, &ResolvedApi)> {
        self.targets
            .iter()
            .map(|(&rva, &i)| (rva, &self.resolved[i]))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Technique {
    pub rule: String,
    pub severity: String,
    pub confidence: String,
    #[serde(serialize_with = "hex_opt")]
    pub rva: Option<u32>,
    pub detail: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolvedApi {
    /// The resolver call: GetProcAddress, a walker, or the inlined walk's call.
    #[serde(serialize_with = "hex")]
    pub site: u32,
    #[serde(serialize_with = "hex")]
    pub function: u32,
    pub method: String,
    pub module: Option<String>,
    pub module_source: String,
    pub api: Option<String>,
    pub api_source: String,
    /// Indirect calls and tail jumps through the resolved pointer.
    #[serde(serialize_with = "hex_list")]
    pub call_sites: Vec<u32>,
}

impl ResolvedApi {
    /// `module!api`, with `?` for whichever part was not recovered.
    pub fn target(&self) -> String {
        format!(
            "{}!{}",
            self.module.as_deref().map_or("?", short_module),
            self.api.as_deref().unwrap_or("?")
        )
    }

    /// The resolver and how the names were hidden, e.g. `GetProcAddress · xor 0x5A`.
    pub fn describe(&self) -> String {
        let mut parts = vec![self.method.clone()];
        for source in [&self.api_source, &self.module_source] {
            if !matches!(source.as_str(), "literal" | "" | "unknown") && !parts.contains(source) {
                parts.push(source.clone());
            }
        }
        parts.join(" · ")
    }
}

fn short_module(name: &str) -> &str {
    let file = name.rsplit(['\\', '/']).next().unwrap_or(name);
    file.strip_suffix(".dll")
        .or_else(|| file.strip_suffix(".DLL"))
        .unwrap_or(file)
}

fn hex<S: Serializer>(value: &u32, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&format!("0x{value:08X}"))
}

fn hex_opt<S: Serializer>(value: &Option<u32>, serializer: S) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => hex(value, serializer),
        None => serializer.serialize_none(),
    }
}

fn hex_list<S: Serializer>(values: &[u32], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(values.iter().map(|value| format!("0x{value:08X}")))
}

/// [`analyze`], once per image per process.
pub fn cached(pe: &PeFile, raw: &[u8]) -> Arc<ResolutionReport> {
    type Key = (usize, usize, u64, u32, u32);
    static CACHE: Mutex<Vec<(Key, Arc<ResolutionReport>)>> = Mutex::new(Vec::new());
    // A freed buffer can be reused for another image, so identity is included.
    let key = (
        raw.as_ptr() as usize,
        raw.len(),
        pe.image_base,
        pe.timestamp,
        pe.entry_point,
    );
    if let Some((_, report)) = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .find(|(cached, _)| *cached == key)
    {
        return report.clone();
    }
    let report = Arc::new(analyze(pe, raw));
    let mut cache = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cache.push((key, report.clone()));
    if cache.len() > 4 {
        cache.remove(0);
    }
    report
}

pub fn analyze(pe: &PeFile, raw: &[u8]) -> ResolutionReport {
    let layout = match pe.machine {
        0x8664 => &machine::X64,
        0x014C => &machine::X86,
        _ => return ResolutionReport::default(),
    };
    let functions = image::discover(pe, raw);
    let mut ctx = context(pe, raw, layout, &functions);
    let run = |ctx: &Context<'_>, function: &image::Function| {
        machine::run(ctx, function, &image::decode(pe, raw, function))
    };
    let mut facts: Vec<Facts> = functions
        .iter()
        .map(|function| {
            let insns = image::decode(pe, raw, function);
            if machine::is_candidate(&ctx, &insns) {
                machine::run(&ctx, function, &insns)
            } else {
                machine::profile(&ctx, function, &insns)
            }
        })
        .collect();

    for _ in 0..MAX_ROUNDS {
        let summaries: HashMap<u32, Summary> = functions
            .iter()
            .zip(&facts)
            .filter_map(|(function, facts)| {
                summarize(function.rva, facts).map(|summary| (function.rva, summary))
            })
            .collect();
        let mut global_api = HashMap::new();
        let mut global_module = HashMap::new();
        for function_facts in &facts {
            for &(va, id) in &function_facts.global_api {
                global_api.entry(va).or_insert(id);
            }
            for (va, module) in &function_facts.global_module {
                global_module.entry(*va).or_insert_with(|| module.clone());
            }
        }
        let changed_functions: HashSet<u32> = summaries
            .iter()
            .filter(|(rva, summary)| ctx.summaries.get(rva) != Some(summary))
            .map(|(rva, _)| *rva)
            .chain(
                ctx.summaries
                    .keys()
                    .filter(|rva| !summaries.contains_key(rva))
                    .copied(),
            )
            .collect();
        let changed_globals: HashSet<u64> = global_api
            .iter()
            .filter(|(va, id)| ctx.global_api.get(va) != Some(id))
            .map(|(va, _)| *va)
            .chain(
                global_module
                    .iter()
                    .filter(|(va, module)| ctx.global_module.get(va) != Some(module))
                    .map(|(va, _)| *va),
            )
            .collect();
        if changed_functions.is_empty() && changed_globals.is_empty() {
            break;
        }
        ctx.summaries = summaries;
        ctx.global_api = global_api;
        ctx.global_module = global_module;
        for (function, function_facts) in functions.iter().zip(facts.iter_mut()) {
            let dirty = function_facts
                .callees
                .iter()
                .any(|callee| changed_functions.contains(callee))
                || function_facts
                    .global_loads
                    .iter()
                    .any(|va| changed_globals.contains(va));
            if dirty {
                *function_facts = run(&ctx, function);
            }
        }
    }
    report(&functions, &facts, &ctx)
}

fn context<'a>(
    pe: &'a PeFile,
    raw: &'a [u8],
    layout: &'static machine::Layout,
    functions: &[image::Function],
) -> Context<'a> {
    let mut imports = HashMap::new();
    for dll in read_imports(pe, raw) {
        for entry in dll.entries {
            imports.insert(
                pe.image_base + u64::from(entry.slot_rva),
                (dll.dll.clone(), entry.name),
            );
        }
    }
    let mut thunks = HashMap::new();
    for function in functions {
        if let Some(slot) = jump_thunk_slot(pe, raw, function.rva) {
            if imports.contains_key(&slot) {
                thunks.insert(function.rva, slot);
            }
        }
    }
    let writable = pe
        .sections
        .iter()
        .filter(|section| section.characteristics & 0x8000_0000 != 0)
        .map(|section| {
            let start = pe.image_base + u64::from(section.virtual_address);
            (
                start,
                start + u64::from(section.virtual_size.max(section.raw_size)),
            )
        })
        .collect();
    let guard_dispatch =
        read_load_config(pe, raw).map_or(0, |load| load.guard_cf_dispatch_function_pointer);
    let mut ret_pops = HashMap::new();
    if layout.args.is_empty() {
        for function in functions {
            let pops = image::decode(pe, raw, function)
                .iter()
                .filter(|insn| insn.mnemonic() == Mnemonic::Ret)
                .map(|insn| {
                    if insn.op_count() == 1 {
                        i64::from(insn.immediate16())
                    } else {
                        0
                    }
                })
                .max();
            if let Some(pops) = pops {
                ret_pops.insert(function.rva, pops);
            }
        }
    }
    Context {
        pe,
        raw,
        layout,
        imports,
        thunks,
        guard_dispatch,
        guard_check: guard_check_slot(pe, raw),
        summaries: HashMap::new(),
        global_api: HashMap::new(),
        global_module: HashMap::new(),
        writable,
        ret_pops,
    }
}

/// The IAT slot a `jmp [slot]` import stub at `rva` jumps through.
fn jump_thunk_slot(pe: &PeFile, raw: &[u8], rva: u32) -> Option<u64> {
    let bytes = pe.rva_bytes(raw, rva)?;
    let mut decoder = Decoder::with_ip(
        pe.arch,
        &bytes[..bytes.len().min(16)],
        pe.image_base + u64::from(rva),
        DecoderOptions::NONE,
    );
    let insn = decoder.decode();
    if insn.mnemonic() != Mnemonic::Jmp || insn.op0_kind() != OpKind::Memory {
        return None;
    }
    match insn.memory_base() {
        Register::RIP | Register::EIP => Some(insn.ip_rel_memory_address()),
        Register::None if insn.memory_index() == Register::None => {
            Some(insn.memory_displacement64())
        }
        _ => None,
    }
}

/// GuardCFCheckFunctionPointer, the slot x86 code calls to validate a target before
/// calling it; that call is not itself a call through the target.
fn guard_check_slot(pe: &PeFile, raw: &[u8]) -> u64 {
    let (rva, size) = pe.data_dir(crate::formats::pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
    let (offset, width) = if pe.arch == 64 { (0x70, 8) } else { (0x48, 4) };
    if rva == 0 || (size as usize) < offset + width {
        return 0;
    }
    pe.rva_slice(raw, rva + offset as u32, width)
        .map_or(0, |bytes| {
            let mut value = [0u8; 8];
            value[..width].copy_from_slice(bytes);
            u64::from_le_bytes(value)
        })
}

/// What callers can rely on this function to return.
fn summarize(rva: u32, facts: &Facts) -> Option<Summary> {
    let params = facts.params;
    // A walk whose result this function calls itself is not offered to callers.
    let calls_own_walk = facts
        .resolutions
        .iter()
        .any(|res| res.via == Via::ExportWalk(rva));
    let returns_export = facts
        .returns
        .iter()
        .any(|value| matches!(value, Val::Export(_)));
    if facts.events.export_walk() && !calls_own_walk && (returns_export || !facts.indirect_unknown)
    {
        return Some(Summary::Api {
            via: Via::ExportWalk(rva),
            name_param: None,
            module: Module::Unknown,
            params,
        });
    }
    if facts.events.import_walk() && !calls_own_walk && !facts.indirect_unknown {
        return Some(Summary::Api {
            via: Via::ImportWalk(rva),
            name_param: None,
            module: Module::Unknown,
            params,
        });
    }
    for value in &facts.returns {
        match value {
            Val::Module(Module::Walk { finder, key }) => {
                let key_param = match key {
                    Name::Param(p) => Some(*p),
                    _ => None,
                };
                if *finder == rva || key_param.is_some() {
                    return Some(Summary::Module {
                        finder: *finder,
                        key_param,
                        loader: false,
                        params,
                    });
                }
                return Some(Summary::ModuleValue(Module::Walk {
                    finder: *finder,
                    key: key.clone(),
                }));
            }
            Val::Module(Module::Loader(Name::Param(p))) => {
                return Some(Summary::Module {
                    finder: rva,
                    key_param: Some(*p),
                    loader: true,
                    params,
                });
            }
            Val::Module(module @ Module::Loader(_)) => {
                return Some(Summary::ModuleValue(module.clone()));
            }
            Val::Api(id) => {
                let Some(res) = facts
                    .resolutions
                    .iter()
                    .find(|res| id.function == rva && res.site == id.site)
                else {
                    return Some(Summary::Fixed(*id));
                };
                let name_param = match res.name {
                    Name::Param(p) => Some(p),
                    _ => None,
                };
                if name_param.is_some() || module_param(&res.module) {
                    return Some(Summary::Api {
                        via: res.via.clone(),
                        name_param,
                        module: res.module.clone(),
                        params,
                    });
                }
                return Some(Summary::Fixed(*id));
            }
            _ => {}
        }
    }
    None
}

fn module_param(module: &Module) -> bool {
    matches!(
        module,
        Module::Param(_)
            | Module::Loader(Name::Param(_))
            | Module::Walk {
                key: Name::Param(_),
                ..
            }
    )
}

struct Inverted {
    apis: HashMap<(u32, u64), (String, String)>,
    modules: HashMap<(u32, u64), (String, String)>,
    /// Walkers whose code (or a direct callee's) does hash-like arithmetic; a
    /// constant passed to any other walker is not presumed to be a hash.
    hashing: HashSet<u32>,
}

impl Inverted {
    fn key_label(&self, walker: u32, value: u64) -> String {
        if self.hashing.contains(&walker) {
            format!("hash 0x{value:X}")
        } else {
            format!("constant 0x{value:X}")
        }
    }
}

/// Hash constants grouped by the function whose walk compares them, inverted over the
/// export and module dictionaries with that function's (and its callees') hints.
fn invert_hashes(rvas: &HashMap<u32, usize>, facts: &[Facts]) -> Inverted {
    let mut api_groups: HashMap<u32, BTreeSet<u64>> = HashMap::new();
    let mut module_groups: HashMap<u32, BTreeSet<u64>> = HashMap::new();
    for (index, function_facts) in facts.iter().enumerate() {
        for res in &function_facts.resolutions {
            if let (Via::ExportWalk(walker) | Via::ImportWalk(walker), Name::Hash(value)) =
                (&res.via, &res.name)
            {
                api_groups.entry(*walker).or_default().insert(*value);
            }
            if let Module::Walk {
                finder,
                key: Name::Hash(value),
            } = &res.module
            {
                module_groups.entry(*finder).or_default().insert(*value);
            }
            // An inlined walk compares its constants in place.
            if let Via::ExportWalk(walker) = res.via {
                if rvas.get(&walker) == Some(&index) {
                    api_groups
                        .entry(walker)
                        .or_default()
                        .extend(&function_facts.compares);
                    module_groups
                        .entry(walker)
                        .or_default()
                        .extend(&function_facts.compares);
                }
            }
        }
    }
    let mut inverted = Inverted {
        apis: HashMap::new(),
        modules: HashMap::new(),
        hashing: HashSet::new(),
    };
    if api_groups.is_empty() && module_groups.is_empty() {
        return inverted;
    }
    let hints = |rva: u32| {
        let mut hints = hashes::Hints::default();
        if let Some(&index) = rvas.get(&rva) {
            hints.merge(&facts[index].hints);
            for callee in &facts[index].callees {
                if let Some(&callee) = rvas.get(callee) {
                    hints.merge(&facts[callee].hints);
                }
            }
        }
        hints
    };
    inverted.hashing = api_groups
        .keys()
        .chain(module_groups.keys())
        .copied()
        .filter(|&rva| hints(rva).any())
        .collect();
    let dictionary = dictionary::get();
    let api_names: Vec<&str> = dictionary.apis.keys().map(String::as_str).collect();
    let module_names: Vec<&str> = dictionary.module_names.iter().map(String::as_str).collect();
    for (groups, names, out) in [
        (&api_groups, &api_names, &mut inverted.apis),
        (&module_groups, &module_names, &mut inverted.modules),
    ] {
        for (&rva, values) in groups {
            let values: Vec<u64> = values.iter().copied().collect();
            if let Some(inversion) = hashes::invert(&values, &hints(rva), names) {
                for (value, name) in inversion.names {
                    out.insert((rva, value), (name, inversion.algorithm.clone()));
                }
            }
        }
    }
    inverted
}

fn how_label(how: &How) -> String {
    match how {
        How::Literal => "literal".to_owned(),
        How::StackString => "stack string".to_owned(),
        How::Decoded(scheme) => scheme.clone(),
    }
}

fn describe_module(module: &Module, inverted: &Inverted) -> (Option<String>, String) {
    match module {
        Module::Loader(Name::Text(text, how)) => (Some(text.clone()), how_label(how)),
        Module::Walk { finder, key } => match key {
            Name::Text(text, how) => (
                Some(text.clone()),
                format!("loader-list walk, {}", how_label(how)),
            ),
            Name::Hash(value) => match inverted.modules.get(&(*finder, *value)) {
                Some((name, algorithm)) => (
                    Some(name.clone()),
                    format!("loader-list walk, {algorithm} hash 0x{value:X}"),
                ),
                None => (
                    None,
                    format!("loader-list walk, {}", inverted.key_label(*finder, *value)),
                ),
            },
            _ => (None, "loader-list walk".to_owned()),
        },
        Module::SelfImage => (Some("<image>".to_owned()), "own image base".to_owned()),
        _ => (None, "unknown".to_owned()),
    }
}

fn report(functions: &[image::Function], facts: &[Facts], ctx: &Context<'_>) -> ResolutionReport {
    let rvas: HashMap<u32, usize> = functions
        .iter()
        .enumerate()
        .map(|(index, function)| (function.rva, index))
        .collect();
    let inverted = invert_hashes(&rvas, facts);
    let dictionary_needed = facts.iter().any(|function_facts| {
        function_facts
            .resolutions
            .iter()
            .any(|res| matches!(res.name, Name::Text(..)) && matches!(res.module, Module::Unknown))
    });

    let mut out = ResolutionReport::default();
    let mut ids: HashMap<ResId, usize> = HashMap::new();
    for (function, function_facts) in functions.iter().zip(facts) {
        for res in &function_facts.resolutions {
            // Resolutions on a caller's behalf are reported at the callers.
            if matches!(res.name, Name::Param(_)) || module_param(&res.module) {
                continue;
            }
            let inline_walk = res.via == Via::ExportWalk(function.rva);
            let method = match &res.via {
                Via::Loader(api) => (*api).to_owned(),
                Via::ExportWalk(_) if inline_walk => "inline export-table walk".to_owned(),
                Via::ExportWalk(walker) => format!("export-table walk sub_{walker:08X}"),
                Via::ImportWalk(walker) => format!("import-table walk sub_{walker:08X}"),
            };
            let walker = match res.via {
                Via::ExportWalk(walker) | Via::ImportWalk(walker) => walker,
                Via::Loader(_) => 0,
            };
            let (api, api_source) = match &res.name {
                Name::Text(text, how) => (Some(text.clone()), how_label(how)),
                Name::Ordinal(ordinal) => (Some(format!("#{ordinal}")), "ordinal".to_owned()),
                Name::Hash(value) => match inverted.apis.get(&(walker, *value)) {
                    Some((name, algorithm)) => {
                        (Some(name.clone()), format!("{algorithm} hash 0x{value:X}"))
                    }
                    None => (None, inverted.key_label(walker, *value)),
                },
                Name::Unknown if inline_walk => {
                    inline_name(&function_facts.compares, walker, &inverted.apis)
                }
                _ => (None, "computed at run time".to_owned()),
            };
            let (mut module, mut module_source) = describe_module(&res.module, &inverted);
            if inline_walk && module.is_none() {
                if let Some((name, algorithm, value)) =
                    function_facts.compares.iter().find_map(|value| {
                        inverted
                            .modules
                            .get(&(walker, *value))
                            .map(|(name, algorithm)| (name.clone(), algorithm.clone(), *value))
                    })
                {
                    module = Some(name);
                    module_source = format!("loader-list walk, {algorithm} hash 0x{value:X}");
                }
            }
            if module.is_none() && dictionary_needed {
                if let Some(owner) = api
                    .as_deref()
                    .and_then(|api| dictionary::get().module_of(api))
                {
                    module = Some(owner.to_owned());
                    module_source = format!("{module_source}, inferred from export name");
                }
            }
            ids.insert(
                ResId {
                    function: function.rva,
                    site: res.site,
                },
                out.resolved.len(),
            );
            out.resolvers.insert(res.site, out.resolved.len());
            out.resolved.push(ResolvedApi {
                site: res.site,
                function: function.rva,
                method,
                module,
                module_source,
                api,
                api_source,
                call_sites: Vec::new(),
            });
        }
    }
    for function_facts in facts {
        for &(site, through) in &function_facts.through {
            let id = match through {
                Through::Api(id) => Some(id),
                Through::Global(va) => ctx.global_api.get(&va).copied(),
            };
            if let Some(&index) = id.and_then(|id| ids.get(&id)) {
                out.targets.insert(site, index);
                out.resolved[index].call_sites.push(site);
            }
        }
    }
    for resolved in &mut out.resolved {
        resolved.call_sites.sort_unstable();
        resolved.call_sites.dedup();
    }
    // Report in address order; resolver sites are unique, so they re-key the indexes.
    let sites: Vec<u32> = out.resolved.iter().map(|resolved| resolved.site).collect();
    out.resolved.sort_by_key(|resolved| resolved.site);
    let positions: HashMap<u32, usize> = out
        .resolved
        .iter()
        .enumerate()
        .map(|(index, resolved)| (resolved.site, index))
        .collect();
    for index in out.targets.values_mut().chain(out.resolvers.values_mut()) {
        *index = positions[&sites[*index]];
    }
    out.techniques = techniques(functions, facts, &out.resolved);
    out.summary = summary(&out.techniques);
    out
}

/// The API an inlined walk compares for, when exactly one of its constants names one.
fn inline_name(
    compares: &[u64],
    walker: u32,
    apis: &HashMap<(u32, u64), (String, String)>,
) -> (Option<String>, String) {
    let hits: Vec<(u64, &(String, String))> = compares
        .iter()
        .filter_map(|value| apis.get(&(walker, *value)).map(|hit| (*value, hit)))
        .collect();
    match hits.as_slice() {
        [(value, (name, algorithm))] => {
            (Some(name.clone()), format!("{algorithm} hash 0x{value:X}"))
        }
        [] => (None, "computed at run time".to_owned()),
        _ => (
            None,
            format!(
                "one of {}",
                hits.iter()
                    .map(|(_, (name, _))| name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ),
    }
}

fn is_hashed(source: &str) -> bool {
    source.contains(" hash 0x") || source.starts_with("hash 0x")
}

fn is_decoded(source: &str) -> bool {
    ["xor", "add 0x", "sub 0x"]
        .iter()
        .any(|scheme| source.contains(scheme))
}

fn evidence_line(resolved: &ResolvedApi) -> String {
    let mut sources = vec![format!("API {}", resolved.api_source)];
    if resolved.module_source != "unknown" {
        sources.push(format!("module {}", resolved.module_source));
    }
    format!(
        "0x{:08X} {} -> {} ({})",
        resolved.site,
        resolved.method,
        resolved.target(),
        sources.join("; ")
    )
}

fn technique(
    rule: &str,
    severity: &str,
    confidence: &str,
    rva: Option<u32>,
    detail: String,
    mut evidence: Vec<String>,
) -> Technique {
    if evidence.len() > MAX_EVIDENCE {
        let more = evidence.len() - MAX_EVIDENCE;
        evidence.truncate(MAX_EVIDENCE);
        evidence.push(format!("... {more} more"));
    }
    Technique {
        rule: rule.to_owned(),
        severity: severity.to_owned(),
        confidence: confidence.to_owned(),
        rva,
        detail,
        evidence,
    }
}

fn list_name(order: Option<machine::Order>) -> &'static str {
    match order {
        Some(machine::Order::Load) => "InLoadOrderModuleList",
        Some(machine::Order::Memory) => "InMemoryOrderModuleList",
        Some(machine::Order::Init) => "InInitializationOrderModuleList",
        None => "a loader list",
    }
}

/// Techniques in decreasing order of suspicion: hand-walked loader structures and
/// hashed names, then hidden names given to the loader API, then plain lookups.
fn techniques(
    functions: &[image::Function],
    facts: &[Facts],
    resolved: &[ResolvedApi],
) -> Vec<Technique> {
    let mut out = Vec::new();
    let walks: Vec<(u32, &Facts)> = functions
        .iter()
        .zip(facts)
        .filter(|(_, facts)| facts.events.module_walk())
        .map(|(function, facts)| (function.rva, facts))
        .collect();
    let exports: Vec<(u32, &Facts)> = functions
        .iter()
        .zip(facts)
        .filter(|(_, facts)| facts.events.export_walk())
        .map(|(function, facts)| (function.rva, facts))
        .collect();
    let imports: Vec<(u32, &Facts)> = functions
        .iter()
        .zip(facts)
        .filter(|(_, facts)| facts.events.import_walk())
        .map(|(function, facts)| (function.rva, facts))
        .collect();
    let hashed: Vec<&ResolvedApi> = resolved
        .iter()
        .filter(|res| is_hashed(&res.api_source) || is_hashed(&res.module_source))
        .collect();

    if !walks.is_empty() {
        out.push(technique(
            "peb-module-walk",
            "high",
            "high",
            walks[0].1.events.peb.or(walks[0].1.events.list),
            format!(
                "{} function(s) find loaded modules by walking the PEB loader lists instead of calling the loader",
                walks.len()
            ),
            walks
                .iter()
                .map(|(rva, facts)| {
                    let entry = if facts.events.entry.is_some() {
                        " -> DllBase/BaseDllName"
                    } else {
                        ""
                    };
                    format!(
                        "sub_{rva:08X}: PEB -> Ldr -> {}{entry}",
                        list_name(facts.events.list_order)
                    )
                })
                .collect(),
        ));
    }
    if !hashed.is_empty() {
        let algorithms: BTreeSet<String> = hashed
            .iter()
            .flat_map(|res| [&res.api_source, &res.module_source])
            .filter(|source| is_hashed(source))
            .filter_map(|source| {
                let source = source.trim_start_matches("loader-list walk, ");
                source.split(" hash 0x").next().map(str::to_owned)
            })
            .filter(|algorithm| !algorithm.is_empty() && !algorithm.starts_with("hash"))
            .collect();
        let detail = if algorithms.is_empty() {
            "APIs or modules are looked up by hash; the hash function was not identified".to_owned()
        } else {
            format!(
                "APIs or modules are looked up by hash ({})",
                algorithms.into_iter().collect::<Vec<_>>().join(", ")
            )
        };
        out.push(technique(
            "api-hashing",
            "high",
            "high",
            Some(hashed[0].site),
            detail,
            hashed.iter().map(|res| evidence_line(res)).collect(),
        ));
    }
    if !exports.is_empty() {
        let severity = if walks.is_empty() && hashed.is_empty() {
            "medium"
        } else {
            "high"
        };
        let confidence = if exports
            .iter()
            .any(|(_, facts)| facts.events.export_fields.is_some())
        {
            "high"
        } else {
            "medium"
        };
        out.push(technique(
            "export-table-walk",
            severity,
            confidence,
            exports[0].1.events.export_dir,
            format!(
                "{} function(s) parse a module's export directory by hand, a GetProcAddress replacement",
                exports.len()
            ),
            exports
                .iter()
                .map(|(rva, facts)| {
                    let origin = match &facts.events.walk_origin {
                        Some(Module::Walk { .. }) => ", module from a loader-list walk",
                        Some(Module::Loader(_)) => ", module from the loader API",
                        Some(Module::SelfImage) => ", own image",
                        _ => "",
                    };
                    format!("sub_{rva:08X}: e_lfanew -> DataDirectory[EXPORT] -> export arrays{origin}")
                })
                .collect(),
        ));
    }
    if !imports.is_empty() {
        out.push(technique(
            "import-table-walk",
            if walks.is_empty() { "medium" } else { "high" },
            "medium",
            imports[0].1.events.import_dir,
            format!(
                "{} function(s) read import descriptors and IAT slots by hand to find API addresses",
                imports.len()
            ),
            imports
                .iter()
                .map(|(rva, _)| {
                    format!("sub_{rva:08X}: e_lfanew -> DataDirectory[IMPORT] -> descriptors/IAT")
                })
                .collect(),
        ));
    }

    let loader: Vec<&ResolvedApi> = resolved
        .iter()
        .filter(|res| !res.method.contains("walk"))
        .collect();
    let decoded: Vec<&ResolvedApi> = loader
        .iter()
        .copied()
        .filter(|res| is_decoded(&res.api_source) || is_decoded(&res.module_source))
        .collect();
    if !decoded.is_empty() {
        out.push(technique(
            "encoded-api-names",
            "high",
            "high",
            Some(decoded[0].site),
            format!(
                "{} API(s) resolved with names decoded at run time, so the names do not appear in the image",
                decoded.len()
            ),
            decoded.iter().map(|res| evidence_line(res)).collect(),
        ));
    }
    let stacked: Vec<&ResolvedApi> = loader
        .iter()
        .copied()
        .filter(|res| res.api_source == "stack string" || res.module_source == "stack string")
        .filter(|res| !decoded.iter().any(|other| other.site == res.site))
        .collect();
    if !stacked.is_empty() {
        out.push(technique(
            "stack-string-api-names",
            "medium",
            "high",
            Some(stacked[0].site),
            format!(
                "{} API(s) resolved with names built on the stack, out of reach of string scans",
                stacked.len()
            ),
            stacked.iter().map(|res| evidence_line(res)).collect(),
        ));
    }
    let unrecovered: Vec<&ResolvedApi> = loader
        .iter()
        .copied()
        .filter(|res| res.api.is_none())
        .collect();
    if !unrecovered.is_empty() {
        // A name the analysis could not follow is not by itself evidence of hiding.
        out.push(technique(
            "unrecovered-api-names",
            "low",
            "medium",
            Some(unrecovered[0].site),
            format!(
                "{} loader-API lookup(s) use a name computed at run time that was not recovered statically",
                unrecovered.len()
            ),
            unrecovered.iter().map(|res| evidence_line(res)).collect(),
        ));
    }
    let plain: Vec<&ResolvedApi> = loader
        .iter()
        .copied()
        .filter(|res| matches!(res.api_source.as_str(), "literal" | "ordinal"))
        .filter(|res| !is_decoded(&res.module_source) && res.module_source != "stack string")
        .collect();
    if !plain.is_empty() {
        out.push(technique(
            "loader-api-resolution",
            "low",
            "high",
            Some(plain[0].site),
            format!(
                "{} API(s) resolved by plain name or ordinal through the loader API",
                plain.len()
            ),
            plain.iter().map(|res| evidence_line(res)).collect(),
        ));
    }
    out
}

fn summary(techniques: &[Technique]) -> String {
    techniques
        .iter()
        .map(|technique| match technique.rule.as_str() {
            "peb-module-walk" => "PEB loader-list walk".to_owned(),
            "api-hashing" => technique
                .detail
                .split_once('(')
                .map_or("API hashing".to_owned(), |(_, algorithms)| {
                    format!("API hashing ({}", algorithms)
                }),
            "export-table-walk" => "manual export-table walk".to_owned(),
            "import-table-walk" => "manual import-table walk".to_owned(),
            "encoded-api-names" => "encoded API names".to_owned(),
            "stack-string-api-names" => "stack-string API names".to_owned(),
            "unrecovered-api-names" => "run-time API names".to_owned(),
            "loader-api-resolution" => "loader API by name".to_owned(),
            other => other.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("; ")
}
