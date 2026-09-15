use super::*;

pub(super) fn profile_image(
    path: &Path,
    side: &str,
    pdb_file: &str,
    mode: &str,
    max_functions: usize,
    cfg: &Config,
) -> Result<ImageProfile, String> {
    let raw = crate::core::input::read_image(path)
        .map_err(|e| format!("read '{}': {}", path.display(), e))?;
    let pe = parse_pe(&raw).map_err(|e| e.0)?;
    let arch = cfg.effective_arch(pe.arch);
    let exports = read_exports(&pe, &raw);
    let imports = read_imports(&pe, &raw);
    let data = read_data_summary(&pe, &raw);
    let startup = find_startup_routines(&pe, &raw);
    let path_str = path.to_string_lossy().to_string();

    let pdb_symbols = if cfg.no_pdb {
        Vec::new()
    } else {
        load_pdb_symbols(
            &path_str,
            &cfg.sym_path,
            &cfg.sym_server,
            pdb_file,
            cfg.verbose,
            cfg.reload,
        )
        .unwrap_or_default()
    };
    let symbol_index = SymbolIndex::from_exports_and_pdb(&exports, &pdb_symbols, pe.image_base);

    let mut discovery_cfg = cfg.clone();
    discovery_cfg.max_total = discovery_cfg.max_total.max(max_functions);
    let discovery = discover_functions(
        &raw,
        &pe,
        &exports,
        &symbol_index,
        &pdb_symbols,
        &startup,
        &discovery_cfg,
    );

    let mut discovered = discovery.functions.clone();
    discovered.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then_with(|| parse_hex32(&a.rva).cmp(&parse_hex32(&b.rva)))
    });
    discovered.truncate(max_functions);
    discovered.sort_by_key(|item| item.rva.clone());

    let import_slots = import_slot_map(&imports);
    let import_names = import_name_set(&imports);
    let export_names = export_name_set(&exports);
    let strings = string_set(&data);
    let string_rvas = data.strings.iter().map(|s| s.rva).collect::<BTreeSet<_>>();

    let mut notes = discovery
        .notes
        .iter()
        .map(|note| format!("{}: {}", side, note))
        .collect::<Vec<_>>();
    if !cfg.no_pdb && pdb_symbols.is_empty() {
        notes.push(format!(
            "{}: PDB symbols were unavailable; diff falls back to static discovery",
            side
        ));
    }
    if discovery.stats.total > max_functions {
        notes.push(format!(
            "{}: profiled {} of {} discovered functions due to --max-functions",
            side, max_functions, discovery.stats.total
        ));
    }

    let mut decode_cfg = decode_config(cfg, mode);
    let mut functions = Vec::new();
    let progress = ProgressBar::new(
        discovered.len(),
        !cfg.quiet && !cfg.json && !discovered.is_empty(),
        false,
    );
    for function in &discovered {
        progress.tick(&format!("{}: {}", side, function.name));
        match profile_function(
            function,
            &raw,
            &pe,
            arch,
            &exports,
            &symbol_index,
            &import_slots,
            &string_rvas,
            &mut decode_cfg,
        ) {
            Ok(Some(fp)) => functions.push(fp),
            Ok(None) => {}
            Err(err) => notes.push(format!("{}: {}: {}", side, function.name, err)),
        }
    }
    progress.finish();
    prune_nested_function_hints(&mut functions, &mut notes, side);

    let import_count = imports.iter().map(|dll| dll.entries.len()).sum();
    let traits = image_traits(&pe, &export_names, &import_names, &strings);
    let summary = DiffImageSummary {
        path: path_str,
        name: path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
        arch: format!("x{}", arch),
        image_base: hex64(pe.image_base),
        entry_point: hex32(pe.entry_point),
        size_bytes: raw.len() as u64,
        exports: exports.len(),
        imports: import_count,
        strings: data.strings.len(),
        discovered_functions: discovery.stats.total,
        profiled_functions: functions.len(),
        sections: section_entropy(&pe),
        notes: dedupe_strings(notes),
    };

    Ok(ImageProfile {
        summary,
        traits,
        functions,
        exports: export_names,
        imports: import_names,
        strings,
    })
}

pub(super) fn indexed_image_from_profile(profile: &ImageProfile) -> IndexedImage {
    IndexedImage {
        summary: profile.summary.clone(),
        traits: profile.traits.clone(),
        exports: profile.exports.iter().cloned().collect(),
        imports: profile.imports.iter().cloned().collect(),
        strings: profile.strings.iter().take(4096).cloned().collect(),
        functions: profile.functions.iter().map(indexed_function).collect(),
    }
}

pub(super) fn indexed_function(fp: &FunctionFingerprint) -> IndexedFunction {
    IndexedFunction {
        name: fp.name.clone(),
        rva: hex32(fp.rva),
        section: fp.section.clone(),
        source: fp.source.clone(),
        confidence: fp.confidence,
        size_bytes: fp.size_bytes,
        insn_count: fp.insn_count,
        block_count: fp.block_count,
        edge_count: fp.edge_count,
        semantic_hash: hex64(fp.semantic_hash),
        cfg_hash: hex64(fp.cfg_hash),
        api_hash: hex64(fp.api_hash),
        fuzzy_hash: hex64(fp.fuzzy_hash),
        shape_tokens: fp.shape_tokens.clone(),
        block_hashes: fp.block_hashes.iter().map(|hash| hex64(*hash)).collect(),
        opcode_ngrams: fp.opcode_ngrams.clone(),
        api_set: fp.api_set.iter().cloned().collect(),
        const_set: fp.const_set.iter().cloned().collect(),
        internal_targets: fp
            .internal_targets
            .iter()
            .map(|target| hex32(*target))
            .collect(),
        noise: fp.noise,
        noise_reason: fp.noise_reason.clone(),
        trait_tags: fp.trait_tags.clone(),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn profile_function(
    function: &DiscoveredFunction,
    raw: &[u8],
    pe: &PeFile,
    arch: u32,
    exports: &[Export],
    symbols: &SymbolIndex,
    import_slots: &BTreeMap<u32, String>,
    string_rvas: &BTreeSet<u32>,
    cfg: &mut Config,
) -> Result<Option<FunctionFingerprint>, String> {
    let Some(rva) = parse_hex32(&function.rva) else {
        return Ok(None);
    };
    let Some(file_off) = pe.rva_to_offset(rva) else {
        return Ok(None);
    };
    if !pe
        .rva_to_section(rva)
        .is_some_and(|section| section.is_executable())
    {
        return Ok(None);
    }

    let insns = disassemble_at(
        raw,
        pe,
        file_off,
        rva,
        arch,
        pe.image_base,
        exports,
        Some(symbols),
        cfg,
    )
    .map_err(|e| format!("disassembly failed: {}", e))?;
    if insns.is_empty() {
        return Ok(None);
    }

    let blocks = build_basic_blocks(&insns, pe.image_base);
    let block_ids = blocks
        .iter()
        .enumerate()
        .map(|(idx, block)| (block.start_rva, idx))
        .collect::<BTreeMap<_, _>>();

    let mut normalized_ops = Vec::with_capacity(insns.len());
    let mut opcodes = Vec::with_capacity(insns.len());
    let mut const_set = BTreeSet::new();
    for insn in &insns {
        let normalized = normalize_instruction(insn, pe, import_slots, string_rvas, &block_ids);
        opcodes.push(normalized.opcode);
        const_set.extend(normalized.constants);
        normalized_ops.push(normalized.text);
    }

    let mut block_hashes = Vec::new();
    let mut shape_tokens = Vec::new();
    for block in &blocks {
        let mut block_ops = Vec::new();
        for insn in &block.insns {
            let normalized = normalize_instruction(insn, pe, import_slots, string_rvas, &block_ids);
            block_ops.push(normalized.text);
        }
        block_hashes.push(stable_hash_tokens(&block_ops));
        shape_tokens.push(format!("block:{}", bucket(block.insns.len() as u64)));
        for edge in &block.edges {
            shape_tokens.push(format!("edge:{}", edge.kind));
        }
    }

    let api_calls = collect_api_calls(&insns, pe, raw, symbols, pe.image_base, cfg.hostile);
    let api_set = api_calls
        .iter()
        .filter_map(normalized_api_call)
        .collect::<BTreeSet<_>>();
    let internal_targets = api_calls
        .iter()
        .filter(|call| !call.is_import && call.target_rva != 0)
        .filter(|call| {
            pe.rva_to_section(call.target_rva)
                .is_some_and(|section| section.is_executable())
        })
        .map(|call| call.target_rva)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let api_hash = stable_hash_tokens(api_set.iter().map(String::as_str));
    let string_ref_count = find_string_refs(raw, pe, &insns).len();

    let size_bytes = function_size(&insns);
    let semantic_hash = stable_hash_tokens(&normalized_ops);
    let cfg_hash = stable_hash_tokens(&shape_tokens);
    let edge_count = blocks.iter().map(|block| block.edges.len()).sum();
    let fuzzy_hash = simhash_tokens(
        shape_tokens
            .iter()
            .chain(opcodes.iter())
            .chain(api_set.iter())
            .map(String::as_str),
    );
    let (noise, noise_reason, trait_tags) = classify_function(FunctionClassification {
        name: &function.name,
        source: &function.source,
        confidence: function.confidence,
        size_bytes,
        insn_count: insns.len(),
        block_count: blocks.len(),
        edge_count,
        api_set: &api_set,
        string_ref_count,
    });

    Ok(Some(FunctionFingerprint {
        name: function.name.clone(),
        rva,
        section: function.section.clone(),
        source: function.source.clone(),
        confidence: function.confidence,
        size_bytes,
        insn_count: insns.len(),
        block_count: blocks.len(),
        edge_count,
        semantic_hash,
        cfg_hash,
        api_hash,
        shape_tokens,
        block_hashes,
        opcode_ngrams: ngrams(&opcodes, 3),
        api_set,
        const_set,
        string_ref_count,
        internal_targets,
        fuzzy_hash,
        noise,
        noise_reason,
        trait_tags,
    }))
}
