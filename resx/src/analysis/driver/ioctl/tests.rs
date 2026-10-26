use super::*;
use crate::formats::pe::PeSection;

fn image(code: &[u8]) -> (PeFile, Vec<u8>) {
    let pe = PeFile {
        arch: 64,
        machine: 0x8664,
        timestamp: 0,
        coff_characteristics: 0x22,
        major_linker_version: 0,
        minor_linker_version: 0,
        image_base: 0x140000000,
        entry_point: 0x1000,
        size_of_image: 0x4000,
        size_of_headers: 0x200,
        section_alignment: 0x1000,
        file_alignment: 0x200,
        checksum: 0,
        subsystem: 1,
        dll_characteristics: 0,
        data_dirs: vec![(0, 0); 16],
        anomalies: vec![],
        sections: vec![
            PeSection {
                name: ".text".into(),
                virtual_address: 0x1000,
                virtual_size: 0x1000,
                raw_offset: 0x200,
                raw_size: 0x1000,
                characteristics: 0x60000020,
                entropy: 0.0,
            },
            PeSection {
                name: ".rdata".into(),
                virtual_address: 0x2000,
                virtual_size: 0x400,
                raw_offset: 0x1200,
                raw_size: 0x400,
                characteristics: 0x40000040,
                entropy: 0.0,
            },
        ],
    };
    let mut raw = vec![0; 0x1600];
    raw[0x200..0x1200].fill(0xcc);
    raw[0x200..0x200 + code.len()].copy_from_slice(code);
    (pe, raw)
}

const LOAD: &[u8] = &[0x48, 0x8b, 0x82, 0xb8, 0, 0, 0, 0x8b, 0x48, 0x18]; // rcx = IRP stack code
fn analyze(code: &[u8]) -> Vec<IoctlCodeCandidate> {
    let (pe, raw) = image(code);
    recover(
        &pe,
        &raw,
        &[Root {
            rva: 0x1000,
            reason: "test registration".into(),
        }],
        &mut Coverage::default(),
    )
}
fn append_compare(code: &mut Vec<u8>, n: u32) {
    code.extend([0x81, 0xf9]);
    code.extend(n.to_le_bytes());
    code.extend([0x74, 0, 0xc3]);
}

#[test]
fn function_zero_and_cumulative_subtraction() {
    let mut code = LOAD.to_vec();
    code.extend([
        0x81, 0xe9, 0, 0, 1, 0, 0x74, 5, 0x83, 0xf9, 4, 0x74, 0, 0xc3,
    ]);
    let found = analyze(&code);
    assert_eq!(
        found.iter().map(|c| c.code.as_str()).collect::<Vec<_>>(),
        ["0x00010000", "0x00010004"]
    );
    assert!(found.iter().all(|c| c
        .evidence_status
        .starts_with("static-request-code-comparison")));
}

#[test]
fn real_dxg_external_code_and_internal_vendor_code() {
    for value in [0x234003, 0x23e057] {
        let mut code = LOAD.to_vec();
        append_compare(&mut code, value);
        assert_eq!(analyze(&code)[0].code, format!("0x{value:08X}"));
    }
}

#[test]
fn constants_thresholds_partial_writes_and_changed_flags_are_not_codes() {
    let mut cases = Vec::new();
    let mut constants = vec![0xb9, 4, 0x20, 0x22, 0];
    append_compare(&mut constants, 0x222008);
    cases.push(constants);
    let mut partial = LOAD.to_vec();
    partial.extend([0xb1, 0]);
    append_compare(&mut partial, 0x222004);
    cases.push(partial);
    let mut threshold = LOAD.to_vec();
    append_compare(&mut threshold, 0x222004);
    let n = threshold.len();
    threshold[n - 3] = 0x77;
    cases.push(threshold);
    let mut flags = LOAD.to_vec();
    flags.extend([0x81, 0xf9, 4, 0x20, 0x22, 0, 0x31, 0xd2, 0x74, 0, 0xc3]);
    cases.push(flags);
    let mut call = LOAD.to_vec();
    call.extend([0xff, 0xd0]); // unknown indirect call clobbers volatile rcx
    append_compare(&mut call, 0x222004);
    cases.push(call);
    let mut shifted = LOAD.to_vec();
    shifted.extend([0xc1, 0xe9, 2]);
    append_compare(&mut shifted, 0x222004);
    cases.push(shifted);
    for (i, code) in cases.iter().enumerate() {
        assert!(analyze(code).is_empty(), "noise case {i}");
    }
}

#[test]
fn partial_stack_overwrite_kills_spilled_code() {
    let mut code = LOAD.to_vec();
    code.extend([
        0x89, 0x4c, 0x24, 0x20, 0xc6, 0x44, 0x24, 0x21, 0, 0x8b, 0x4c, 0x24, 0x20,
    ]);
    append_compare(&mut code, 0x222004);
    assert!(analyze(&code).is_empty());
}

#[test]
fn no_registered_root_means_no_dispatch_guess() {
    let mut code = LOAD.to_vec();
    append_compare(&mut code, 0x222004);
    let (pe, raw) = image(&code);
    assert!(recover(&pe, &raw, &[], &mut Coverage::default()).is_empty());
}

#[test]
fn unsigned_range_excludes_impossible_equality() {
    let mut code = LOAD.to_vec();
    code.extend([0x81, 0xf9, 0, 0, 1, 0, 0x73, 9]); // >= 0x10000 skips equality
    append_compare(&mut code, 0x222004);
    code.push(0xc3);
    assert!(analyze(&code).is_empty());
}

fn table_fixture() -> (PeFile, Vec<u8>) {
    // r9d=request, eax=(request>>2)&0x3ff, bound=2. Exact request
    // comparison in the code table, followed by indexed pointer-table load.
    let mut code = vec![
        0x48, 0x8b, 0x9a, 0xb8, 0, 0, 0, 0x44, 0x8b, 0x4b, 0x18, 0x41, 0x8b, 0xc1, 0xc1, 0xe8, 2,
        0x25, 0xff, 3, 0, 0, 0x83, 0xf8, 2, 0x73, 0x24, 0x48, 0xba,
    ];
    code.extend(0x140000000u64.to_le_bytes());
    code.extend([
        0x44, 0x39, 0x8c, 0x82, 0, 0x20, 0, 0, 0x75, 0x10, 0x48, 0x8b, 0x84, 0xc2, 0x80, 0x20, 0,
        0, 0xc3,
    ]);
    code.resize(64, 0xc3);
    let (pe, mut raw) = image(&code);
    raw[0x1200..0x1208].copy_from_slice(&[3, 0x20, 1, 0, 7, 0x20, 1, 0]);
    raw[0x1280..0x1288].copy_from_slice(&0x140001100u64.to_le_bytes());
    raw[0x1288..0x1290].copy_from_slice(&0x140001200u64.to_le_bytes());
    (pe, raw)
}

#[test]
fn validated_indexed_code_and_handler_tables() {
    let (pe, raw) = table_fixture();
    let roots = [Root {
        rva: 0x1000,
        reason: "table fixture".into(),
    }];
    let found = recover(&pe, &raw, &roots, &mut Coverage::default());
    assert_eq!(
        found.iter().map(|c| c.code.as_str()).collect::<Vec<_>>(),
        ["0x00012003", "0x00012007"]
    );
    assert_eq!(found[1].handler_rva.as_deref(), Some("0x00001200"));
    for variant in 0..5 {
        let mut pe = pe.clone();
        let mut raw = raw.clone();
        match variant {
            0 => raw[0x1200..0x1208].fill(0xff), // wrong request->index mapping
            1 => raw[0x1280..0x1290].fill(0),    // null handlers
            2 => raw[0x1280..0x1288].copy_from_slice(&0x140002100u64.to_le_bytes()), // data pointer
            3 => pe.sections[1].characteristics |= 0x80000000, // mutable tables
            _ => raw[0x200 + 25] = 0x74,         // equality is not an unsigned bounds check
        }
        let result = recover(&pe, &raw, &roots, &mut Coverage::default());
        assert_eq!(
            result.len(),
            if variant == 2 { 1 } else { 0 },
            "table noise variant {variant}"
        );
    }
}

#[test]
fn loop_and_root_budgets_are_bounded_and_reported() {
    let (pe, raw) = image(&[0xeb, 0xfe]);
    let mut coverage = Coverage::default();
    recover(
        &pe,
        &raw,
        &vec![
            Root {
                rva: 0x1000,
                reason: "loop".into()
            };
            65
        ],
        &mut coverage,
    );
    assert!(coverage.dispatch_analysis_truncated);
    assert_eq!(coverage.analyzed_roots, 64);
    assert!(coverage.decoded_dispatch_instructions <= 64);
}

fn class_fixture() -> (PeFile, Vec<u8>) {
    // Save DRIVER_OBJECT; construct only the callback field of a local
    // CLASS_INIT_DATA and pass it to the named classpnp import.
    let mut code = vec![
        0x48, 0x8b, 0xd9, 0x48, 0x83, 0xec, 0x78, 0x48, 0x8d, 0x05, 0xf2, 0, 0, 0, 0x48, 0x89,
        0x44, 0x24, 0x68, 0x4c, 0x8d, 0x44, 0x24, 0x40, 0x48, 0x8b, 0xcb,
    ];
    // call [rip+IAT] at RVA 0x101b, next RVA 0x1021
    code.extend([0xff, 0x15]);
    code.extend((0x22c0i32 - 0x1021).to_le_bytes());
    code.push(0xc3);
    let (mut pe, mut raw) = image(&code);
    pe.data_dirs[1] = (0x2200, 40);
    raw[0x1400..0x1404].copy_from_slice(&0x22a0u32.to_le_bytes());
    raw[0x140c..0x1410].copy_from_slice(&0x2280u32.to_le_bytes());
    raw[0x1410..0x1414].copy_from_slice(&0x22c0u32.to_le_bytes());
    raw[0x1480..0x148d].copy_from_slice(b"classpnp.sys\0");
    raw[0x14a0..0x14a8].copy_from_slice(&0x22e0u64.to_le_bytes());
    raw[0x14c0..0x14c8].copy_from_slice(&0x22e0u64.to_le_bytes());
    raw[0x14e2..0x14f2].copy_from_slice(b"ClassInitialize\0");
    (pe, raw)
}

#[test]
fn class_callback_requires_provider_driver_argument_and_code_pointer() {
    let (pe, raw) = class_fixture();
    let discovery = super::super::dispatch::recover(&pe, &raw, &[]);
    assert_eq!(discovery.callbacks.len(), 1);
    assert_eq!(discovery.callbacks[0].rva, 0x1100);
    assert!(discovery.major_functions.is_empty()); // callback is not a fabricated MajorFunction store
    for variant in 0..3 {
        let mut raw = raw.clone();
        match variant {
            0 => raw[0x1480] = b'x', // unrelated provider importing a name with the same spelling
            1 => raw[0x200 + 26] = 0xc8, // rcx = rax (callback address), not DRIVER_OBJECT
            _ => raw[0x200 + 10..0x200 + 14].copy_from_slice(&0x11f2u32.to_le_bytes()), // data callback
        }
        assert!(
            super::super::dispatch::recover(&pe, &raw, &[])
                .callbacks
                .is_empty(),
            "class noise {variant}"
        );
    }
}

#[test]
fn status_writes_do_not_erase_request_but_code_field_writes_do() {
    let mut code = LOAD[..7].to_vec();
    code.extend([0xc7, 0x42, 0x30, 0, 0, 0, 0]); // IRP.IoStatus.Status, unrelated to request
    code.extend(&LOAD[7..]);
    append_compare(&mut code, 0x70000);
    assert_eq!(analyze(&code).len(), 1);
    let mut overwrite = LOAD[..7].to_vec();
    overwrite.extend([0xc7, 0x40, 0x18, 0, 0, 0, 0]); // overwrite IoControlCode
    overwrite.extend(&LOAD[7..]);
    append_compare(&mut overwrite, 0x70000);
    assert!(analyze(&overwrite).is_empty());
}

#[test]
fn known_false_path_does_not_invent_a_request_comparison() {
    let mut code = LOAD.to_vec();
    code.extend([0x31, 0xc0, 0x85, 0xc0, 0x75, 1, 0xc3]); // xor/test eax; jne dead; ret
    append_compare(&mut code, 0x222004);
    assert!(analyze(&code).is_empty());
}

#[test]
fn lea_normalization_retains_request_provenance() {
    let mut code = LOAD.to_vec();
    code.extend([0x8d, 0x89, 0, 0, 0xff, 0xff]); // lea ecx,[rcx-0x10000]
    append_compare(&mut code, 4);
    assert_eq!(analyze(&code)[0].code, "0x00010004");
}
