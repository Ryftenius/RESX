use super::*;
use crate::formats::pe::{PeAnomaly, PeSection, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ};

fn startup_test_pe(entry_point: u32) -> PeFile {
    PeFile {
        arch: 64,
        machine: 0x8664,
        timestamp: 0,
        coff_characteristics: 0,
        major_linker_version: 0,
        minor_linker_version: 0,
        image_base: 0x1800_0000,
        entry_point,
        size_of_image: 0xA000,
        size_of_headers: 0x400,
        section_alignment: 0x1000,
        file_alignment: 0x200,
        checksum: 0,
        subsystem: 3,
        dll_characteristics: 0,
        sections: vec![PeSection {
            name: ".text".to_owned(),
            virtual_address: 0x1000,
            virtual_size: 0x9000,
            raw_offset: 0,
            raw_size: 0x9000,
            characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
            entropy: 0.0,
        }],
        data_dirs: vec![(0, 0); 16],
        anomalies: Vec::<PeAnomaly>::new(),
    }
}

fn put(raw: &mut [u8], rva: u32, bytes: &[u8]) {
    let off = rva.saturating_sub(0x1000) as usize;
    raw[off..off + bytes.len()].copy_from_slice(bytes);
}

#[test]
fn startup_routines_do_not_export_recursive_branch_chains() {
    let pe = startup_test_pe(0x1000);
    let mut raw = vec![0xCC; 0x9000];
    put(&mut raw, 0x1000, &[0xE8, 0xFB, 0x0F, 0x00, 0x00, 0xC3]);
    put(&mut raw, 0x2000, &[0xE8, 0xFB, 0x0F, 0x00, 0x00, 0xC3]);
    put(&mut raw, 0x3000, &[0x48, 0x83, 0xEC, 0x28, 0xC3]);

    let routines = find_startup_routines(&pe, &raw);

    assert!(routines
        .iter()
        .any(|entry| entry.kind == "PE Entry Point" && entry.rva == 0x1000));
    assert_eq!(
        routines
            .iter()
            .filter(|entry| entry.kind == "Startup Handoff")
            .count(),
        1
    );
    assert!(!routines.iter().any(|entry| entry.kind == "Startup Chain"));
}

#[test]
fn startup_routines_reject_raw_rva_immediates_as_main_candidates() {
    let pe = startup_test_pe(0x1000);
    let mut raw = vec![0xCC; 0x9000];
    put(
        &mut raw,
        0x1000,
        &[
            0x48, 0xB8, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE8, 0xF1, 0x0F, 0x00,
            0x00, 0xC3,
        ],
    );
    put(&mut raw, 0x2000, &[0x48, 0x83, 0xEC, 0x28, 0xC3]);
    put(&mut raw, 0x8000, &[0x48, 0x83, 0xEC, 0x28, 0xC3]);

    let routines = find_startup_routines(&pe, &raw);

    assert!(!routines
        .iter()
        .any(|entry| entry.kind == "Real Main Candidate" && entry.rva == 0x8000));
}

#[test]
fn startup_routines_accept_full_va_code_pointer_candidates() {
    let pe = startup_test_pe(0x1000);
    let mut raw = vec![0xCC; 0x9000];
    let mut entry = vec![0x48, 0xB8];
    entry.extend_from_slice(&(pe.image_base + 0x3000).to_le_bytes());
    entry.extend_from_slice(&[0xE8, 0xF1, 0x0F, 0x00, 0x00, 0xC3]);
    put(&mut raw, 0x1000, &entry);
    put(&mut raw, 0x2000, &[0x48, 0x83, 0xEC, 0x28, 0xC3]);
    put(&mut raw, 0x3000, &[0x48, 0x83, 0xEC, 0x28, 0xC3]);

    let routines = find_startup_routines(&pe, &raw);

    assert!(routines
        .iter()
        .any(|entry| entry.kind == "Real Main Candidate" && entry.rva == 0x3000));
}

#[test]
fn startup_routines_reject_odd_code_pointer_candidates() {
    let pe = startup_test_pe(0x1000);
    let mut raw = vec![0xCC; 0x9000];
    let mut entry = vec![0x48, 0xB8];
    entry.extend_from_slice(&(pe.image_base + 0x3001).to_le_bytes());
    entry.extend_from_slice(&[0xE8, 0xF1, 0x0F, 0x00, 0x00, 0xC3]);
    put(&mut raw, 0x1000, &entry);
    put(&mut raw, 0x2000, &[0x48, 0x83, 0xEC, 0x28, 0xC3]);
    put(&mut raw, 0x3001, &[0x48, 0x83, 0xEC, 0x28, 0xC3]);

    let routines = find_startup_routines(&pe, &raw);

    assert!(!routines
        .iter()
        .any(|entry| entry.kind == "Real Main Candidate" && entry.rva == 0x3001));
}
