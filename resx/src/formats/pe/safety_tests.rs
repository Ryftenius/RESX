use super::*;

fn image() -> PeFile {
    PeFile {
        arch: 64,
        machine: 0x8664,
        timestamp: 0,
        coff_characteristics: 0x2022,
        major_linker_version: 0,
        minor_linker_version: 0,
        image_base: 0x180000000,
        entry_point: 0x1000,
        size_of_image: 0x3000,
        size_of_headers: 0x200,
        section_alignment: 0x1000,
        file_alignment: 0x200,
        checksum: 0,
        subsystem: 3,
        dll_characteristics: 0,
        sections: vec![PeSection {
            name: ".text".into(),
            virtual_address: 0x1000,
            virtual_size: 0x1000,
            raw_offset: 0x200,
            raw_size: 0x200,
            characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
            entropy: 0.0,
        }],
        data_dirs: vec![(0, 0); 16],
        anomalies: Vec::new(),
    }
}

#[test]
fn zero_fill_is_not_file_data() {
    let pe = image();
    assert!(pe.rva_to_section(0x1500).is_some());
    assert_eq!(pe.rva_to_offset(0x1500), None);
    assert!(pe.rva_slice(&[0; 0x400], 0x11ff, 2).is_none());
    assert!(pe.rva_slice(&[0; 0x400], 0x11ff, 1).is_some());
}

#[test]
fn tls_startup_order_preserves_duplicates_instead_of_sorting_by_address() {
    let mut pe = image();
    pe.entry_point = 0;
    pe.data_dirs[9] = (0x1040, 40);
    let mut raw = vec![0u8; 0x400];
    raw[0x258..0x260].copy_from_slice(&(pe.image_base + 0x1080).to_le_bytes());
    for (index, rva) in [0x1020u64, 0x1010, 0x1020].iter().enumerate() {
        raw[0x280 + index * 8..0x288 + index * 8]
            .copy_from_slice(&(pe.image_base + rva).to_le_bytes());
    }
    let callbacks: Vec<_> = find_startup_routines(&pe, &raw)
        .into_iter()
        .filter(|r| r.kind == "TLS Callback")
        .map(|r| r.rva)
        .collect();
    assert_eq!(callbacks, [0x1020, 0x1010, 0x1020]);
}

#[test]
fn scalar_reads_do_not_wrap_offsets() {
    assert_eq!(read_u16(&[], usize::MAX), 0);
    assert_eq!(read_u32(&[], usize::MAX), 0);
    assert_eq!(read_u64(&[], usize::MAX), 0);
}

#[test]
fn strings_require_terminators_and_valid_encoding_inside_the_region() {
    assert_eq!(read_cstr_checked(b"name\0", 0, 5).as_deref(), Some("name"));
    assert!(read_cstr_checked(b"name\0", 0, 4).is_none());
    assert!(read_cstr_checked(&[0xff, 0], 0, 2).is_none());
    assert!(read_cstr_checked(b"name", usize::MAX, 4).is_none());
}

#[test]
fn overlapping_virtual_sections_are_ambiguous() {
    let mut pe = image();
    pe.sections.push(pe.sections[0].clone());
    assert!(pe.rva_to_section(0x1000).is_none());
    assert!(pe.rva_slice(&[0; 0x400], 0x1000, 1).is_none());
}

#[test]
fn header_rvas_map_without_inventing_a_section() {
    let pe = image();
    assert_eq!(pe.rva_to_offset(0x100), Some(0x100));
    assert!(pe.rva_to_section(0x100).is_none());
}

#[test]
fn mapped_slices_stop_before_an_overlapping_region() {
    let mut pe = image();
    let mut overlap = pe.sections[0].clone();
    overlap.virtual_address = 0x1100;
    pe.sections.push(overlap);
    assert!(pe.rva_slice(&[0; 0x400], 0x1000, 0x100).is_some());
    assert!(pe.rva_slice(&[0; 0x400], 0x1000, 0x101).is_none());
    assert!(pe.file_offset_to_rva(0x200).is_none());
}

#[test]
fn sections_cannot_shadow_header_mapping() {
    let mut pe = image();
    pe.sections[0].virtual_address = 0x100;
    assert!(pe.rva_to_offset(0x100).is_none());
    assert!(pe.rva_slice(&[0; 0x400], 0, 0x101).is_none());
}

#[test]
fn non_x64_exception_data_is_not_decoded_as_x64_unwind() {
    let mut pe = image();
    pe.machine = 0xaa64;
    assert!(read_runtime_functions(&pe, &[0; 0x400]).is_empty());
}

#[test]
fn unwind_requires_a_complete_supported_record() {
    let pe = image();
    let mut raw = vec![0u8; 0x400];
    raw[0x300] = 1;
    assert!(super::metadata::validate_unwind_chain(&pe, &raw, 0x1000, 0x1010, 0x1100).is_some());
    // Unsupported version and missing extra slots are rejected locally. These
    // are unit-level contracts, not files intended to reproduce another tool's crash.
    raw[0x300] = 7;
    assert!(super::metadata::validate_unwind_chain(&pe, &raw, 0x1000, 0x1010, 0x1100).is_none());
    raw[0x300] = 1;
    raw[0x302] = 1;
    raw[0x305] = 1;
    assert!(super::metadata::validate_unwind_chain(&pe, &raw, 0x1000, 0x1010, 0x1100).is_none());
}

#[test]
fn unwind_chain_does_not_revisit_a_record() {
    let pe = image();
    let mut raw = vec![0u8; 0x400];
    raw[0x300] = 1 | (4 << 3);
    raw[0x304..0x308].copy_from_slice(&0x1000u32.to_le_bytes());
    raw[0x308..0x30c].copy_from_slice(&0x1010u32.to_le_bytes());
    raw[0x30c..0x310].copy_from_slice(&0x1100u32.to_le_bytes());
    assert!(super::metadata::validate_unwind_chain(&pe, &raw, 0x1000, 0x1010, 0x1100).is_none());
}

#[test]
fn resource_directory_cycles_are_reported_without_recursion() {
    let mut pe = image();
    pe.data_dirs[2] = (0x1000, 0x80);
    let mut raw = vec![0; 0x400];
    raw[0x20e..0x210].copy_from_slice(&1u16.to_le_bytes());
    raw[0x214..0x218].copy_from_slice(&0x8000_0000u32.to_le_bytes());
    let findings = super::validation::check(&pe, &raw);
    assert!(findings
        .iter()
        .any(|finding| finding.detail.contains("resource tree cycles")));
}

#[test]
fn resource_leaf_data_must_stay_inside_a_backed_region() {
    let mut pe = image();
    pe.data_dirs[2] = (0x1000, 0x80);
    let mut raw = vec![0; 0x400];
    raw[0x20e..0x210].copy_from_slice(&1u16.to_le_bytes());
    raw[0x214..0x218].copy_from_slice(&0x20u32.to_le_bytes());
    raw[0x220..0x224].copy_from_slice(&0x1080u32.to_le_bytes());
    raw[0x224..0x228].copy_from_slice(&4u32.to_le_bytes());
    assert!(super::validation::check(&pe, &raw).is_empty());
    raw[0x224..0x228].copy_from_slice(&0x1000u32.to_le_bytes());
    assert!(!super::validation::check(&pe, &raw).is_empty());
}

#[test]
fn relocations_require_progress_and_a_mapped_target() {
    let mut pe = image();
    pe.data_dirs[5] = (0x1000, 10);
    let mut raw = vec![0; 0x400];
    raw[0x200..0x204].copy_from_slice(&0x1000u32.to_le_bytes());
    raw[0x204..0x208].copy_from_slice(&10u32.to_le_bytes());
    raw[0x208..0x20a].copy_from_slice(&0xa080u16.to_le_bytes());
    assert!(super::validation::check(&pe, &raw).is_empty());
    raw[0x204..0x208].copy_from_slice(&0u32.to_le_bytes());
    assert!(!super::validation::check(&pe, &raw).is_empty());
}

#[test]
fn certificate_directory_uses_file_offsets_and_bounded_lengths() {
    let mut pe = image();
    pe.data_dirs[4] = (0x300, 16);
    let mut raw = vec![0; 0x400];
    raw[0x300..0x304].copy_from_slice(&16u32.to_le_bytes());
    raw[0x304..0x306].copy_from_slice(&0x200u16.to_le_bytes());
    assert!(super::validation::check(&pe, &raw).is_empty());
    raw[0x300..0x304].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(!super::validation::check(&pe, &raw).is_empty());
}

#[test]
fn import_descriptors_need_an_in_extent_terminator() {
    let mut pe = image();
    pe.data_dirs[1] = (0x1000, 19);
    let raw = vec![0; 0x400];
    assert!(!super::validation::check(&pe, &raw).is_empty());
    pe.data_dirs[1].1 = 20;
    assert!(super::validation::check(&pe, &raw).is_empty());
}

#[test]
fn tls_raw_extent_index_and_zero_fill_are_independently_checked() {
    let mut pe = image();
    pe.data_dirs[9] = (0x1000, 40);
    let mut raw = vec![0; 0x400];
    raw[0x210..0x218].copy_from_slice(&(pe.image_base + 0x1100).to_le_bytes());
    assert!(super::validation::check(&pe, &raw).is_empty());
    raw[0x220..0x224].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(!super::validation::check(&pe, &raw).is_empty());
}

#[test]
fn load_configuration_does_not_trust_oversized_tables() {
    let mut pe = image();
    pe.data_dirs[10] = (0x1000, 148);
    let mut raw = vec![0; 0x400];
    raw[0x200..0x204].copy_from_slice(&148u32.to_le_bytes());
    assert!(super::validation::check(&pe, &raw).is_empty());
    raw[0x288..0x290].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(!super::validation::check(&pe, &raw).is_empty());
}

#[test]
fn guard_iat_and_eh_tables_honor_the_metadata_stride() {
    let mut pe = image();
    pe.data_dirs[10] = (0x1000, 280);
    let mut raw = vec![0; 0x400];
    raw[0x200..0x204].copy_from_slice(&280u32.to_le_bytes());
    raw[0x290..0x294].copy_from_slice(&0x1000_0000u32.to_le_bytes());
    for (pointer, count) in [(160, 168), (264, 272)] {
        raw[0x200 + pointer..0x208 + pointer]
            .copy_from_slice(&(pe.image_base + 0x1180).to_le_bytes());
        raw[0x200 + count..0x208 + count].copy_from_slice(&2u64.to_le_bytes());
    }
    raw[0x380..0x384].copy_from_slice(&0x1100u32.to_le_bytes());
    raw[0x385..0x389].copy_from_slice(&0x1110u32.to_le_bytes());
    assert!(super::validation::check(&pe, &raw).is_empty());
}

#[test]
fn unwind_version_two_without_epilog_prefix_uses_common_prologue_encoding() {
    let mut pe = image();
    pe.data_dirs[3] = (0x1000, 12);
    let mut raw = vec![0; 0x400];
    raw[0x200..0x204].copy_from_slice(&0x1000u32.to_le_bytes());
    raw[0x204..0x208].copy_from_slice(&0x1010u32.to_le_bytes());
    raw[0x208..0x20c].copy_from_slice(&0x1100u32.to_le_bytes());
    raw[0x300] = 2;
    let findings = super::metadata::metadata_anomalies(&pe, &raw);
    assert!(!findings
        .iter()
        .any(|finding| finding.kind == "unwind-unsupported"));
    assert!(!findings
        .iter()
        .any(|finding| finding.kind == "unwind-validation"));
    assert_eq!(read_runtime_functions(&pe, &raw).len(), 1);
}

#[test]
fn missing_entry_and_ret_shaped_data_do_not_become_startup_or_epilog_claims() {
    let mut pe = image();
    pe.entry_point = 0;
    let raw = vec![0xc3; 0x400];
    assert!(!find_startup_routines(&pe, &raw)
        .iter()
        .any(|item| item.kind == "PE Entry Point"));
    pe.entry_point = 0x1000;
    pe.sections[0].characteristics = IMAGE_SCN_MEM_READ;
    assert!(!find_startup_routines(&pe, &raw)
        .iter()
        .any(|item| item.kind == "PE Entry Point"));
}

#[test]
fn unwind_metadata_does_not_prove_executable_file_bytes() {
    let mut pe = image();
    pe.data_dirs[3] = (0x1000, 12);
    pe.sections[0].characteristics = IMAGE_SCN_MEM_READ;
    let mut raw = vec![0; 0x400];
    raw[0x200..0x204].copy_from_slice(&0x1500u32.to_le_bytes());
    raw[0x204..0x208].copy_from_slice(&0x1510u32.to_le_bytes());
    raw[0x208..0x20c].copy_from_slice(&0x1100u32.to_le_bytes());
    raw[0x300] = 1;
    let findings = super::metadata::metadata_anomalies(&pe, &raw);
    assert!(findings
        .iter()
        .any(|finding| finding.kind == "runtime-function-storage"));
    assert!(!findings
        .iter()
        .any(|finding| finding.kind == "unwind-validation"));
    let functions = read_runtime_functions(&pe, &raw);
    assert_eq!(functions.len(), 1);
    assert!(functions[0].epilog_scopes.is_empty());
    assert!(pe.rva_bytes(&raw, 0x1500).is_none());
}

#[test]
fn unavailable_unwind_links_and_handlers_remain_unknown_but_cycles_are_invalid() {
    let mut pe = image();
    pe.data_dirs[3] = (0x1000, 12);
    let mut raw = vec![0; 0x400];
    for (offset, value) in [(0x200, 0x1000u32), (0x204, 0x1010), (0x208, 0x1100)] {
        raw[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    raw[0x300] = 1 | (4 << 3);
    for (offset, value) in [(0x304, 0x1000u32), (0x308, 0x1010), (0x30c, 0x1500)] {
        raw[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    let findings = super::metadata::metadata_anomalies(&pe, &raw);
    assert!(findings.iter().any(|a| a.kind == "unwind-unavailable"));
    assert!(!findings.iter().any(|a| a.kind == "unwind-validation"));
    assert!(read_runtime_functions(&pe, &raw).is_empty());
    raw[0x30c..0x310].copy_from_slice(&0x1100u32.to_le_bytes());
    assert!(super::metadata::metadata_anomalies(&pe, &raw)
        .iter()
        .any(|a| a.kind == "unwind-validation"));
    raw[0x300] = 1 | (1 << 3);
    raw[0x304..0x308].copy_from_slice(&0x1500u32.to_le_bytes());
    assert!(super::metadata::metadata_anomalies(&pe, &raw)
        .iter()
        .any(|a| a.kind == "unwind-unavailable"));
    raw[0x304..0x308].copy_from_slice(&0xfffffffcu32.to_le_bytes());
    assert!(super::metadata::metadata_anomalies(&pe, &raw)
        .iter()
        .any(|a| a.kind == "unwind-validation"));
}

#[test]
fn unwind_semantic_mismatches_do_not_hide_structural_chain_failures() {
    let mut pe = image();
    pe.data_dirs[3] = (0x1000, 12);
    let mut raw = vec![0; 0x400];
    for (offset, value) in [(0x200, 0x1000u32), (0x204, 0x1010), (0x208, 0x1100)] {
        raw[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    raw[0x300] = 1;
    raw[0x301] = 32;
    assert!(super::metadata::metadata_anomalies(&pe, &raw)
        .iter()
        .any(|a| a.kind == "unwind-semantics"));
    assert!(read_runtime_functions(&pe, &raw).is_empty());
    raw[0x300] = 1 | (4 << 3);
    for (offset, value) in [(0x304, 0x1000u32), (0x308, 0x1010), (0x30c, 0x1100)] {
        raw[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    let findings = super::metadata::metadata_anomalies(&pe, &raw);
    assert!(findings.iter().any(|a| a.kind == "unwind-validation"));
    assert!(!findings.iter().any(|a| a.kind == "unwind-semantics"));
    raw[0x30c..0x310].copy_from_slice(&0xfffffffcu32.to_le_bytes());
    assert!(super::metadata::metadata_anomalies(&pe, &raw)
        .iter()
        .any(|a| a.kind == "unwind-validation"));
}

#[test]
fn debug_record_checks_both_file_offset_and_rva() {
    let mut pe = image();
    pe.data_dirs[6] = (0x1000, 28);
    let mut raw = vec![0; 0x400];
    raw[0x210..0x214].copy_from_slice(&4u32.to_le_bytes());
    raw[0x214..0x218].copy_from_slice(&0x1100u32.to_le_bytes());
    raw[0x218..0x21c].copy_from_slice(&0x300u32.to_le_bytes());
    assert!(super::validation::check(&pe, &raw).is_empty());
    raw[0x218..0x21c].copy_from_slice(&0x301u32.to_le_bytes());
    assert!(!super::validation::check(&pe, &raw).is_empty());
}

#[test]
fn clr_version_length_cannot_escape_metadata_directory() {
    let mut pe = image();
    pe.data_dirs[14] = (0x1000, 72);
    let mut raw = vec![0; 0x400];
    raw[0x200..0x204].copy_from_slice(&72u32.to_le_bytes());
    raw[0x208..0x20c].copy_from_slice(&0x1100u32.to_le_bytes());
    raw[0x20c..0x210].copy_from_slice(&24u32.to_le_bytes());
    raw[0x300..0x304].copy_from_slice(b"BSJB");
    raw[0x30c..0x310].copy_from_slice(&4u32.to_le_bytes());
    raw[0x310..0x314].copy_from_slice(b"v1\0\0");
    assert!(super::validation::check(&pe, &raw).is_empty());
    raw[0x30c..0x310].copy_from_slice(&4096u32.to_le_bytes());
    assert!(!super::validation::check(&pe, &raw).is_empty());
}
