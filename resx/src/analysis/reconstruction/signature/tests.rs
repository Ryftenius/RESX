use super::*;
use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};

fn decode(bytes: &[u8], arch: u32) -> Vec<Instruction> {
    decode_at(bytes, arch, 0x1000, 0x1000)
}

fn decode_at(bytes: &[u8], arch: u32, ip: u64, block_start: u32) -> Vec<Instruction> {
    let mut decoder = Decoder::with_ip(arch, bytes, ip, DecoderOptions::NONE);
    let mut rows = Vec::new();
    while decoder.can_decode() {
        let ins = decoder.decode();
        let offset = (ins.ip() - ip) as usize;
        let mut text = String::new();
        IntelFormatter::new().format(&ins, &mut text);
        rows.push(Instruction {
            block_start,
            rva: ins.ip() as u32,
            va: ins.ip(),
            file_off: offset as u64,
            bytes: bytes[offset..offset + ins.len()].to_vec(),
            text,
            mnemonic: String::new(),
            operands: String::new(),
            comment: String::new(),
            is_call: matches!(
                ins.flow_control(),
                FlowControl::Call | FlowControl::IndirectCall
            ),
            is_jmp: ins.mnemonic() == Mnemonic::Jmp,
            is_jcc: ins.flow_control() == FlowControl::ConditionalBranch,
            call_target: 0,
            iced: ins,
        });
    }
    rows
}
fn sig(bytes: &[u8]) -> FunctionSignature {
    infer(&decode(bytes, 64), 0x1000, 64, "test", "")
}

#[test]
fn scalar_parameters_and_return_have_machine_widths() {
    let s = sig(&[0x89, 0xc8, 0x01, 0xd0, 0xc3]); // eax=ecx; eax+=edx
    assert_eq!(s.return_type, "int32_t");
    assert_eq!(s.parameters.len(), 2);
    assert_eq!(s.parameters[0].inferred_type, "int32_t");
    assert!(!s.argument_count_complete);
}
#[test]
fn aliases_preserve_pointer_access() {
    let s = sig(&[0x48, 0x89, 0xc8, 0x8b, 0x00, 0x89, 0x02, 0xc3]);
    assert_eq!(s.parameters[0].inferred_type, "const void *");
    assert_eq!(s.parameters[1].inferred_type, "void *");
}
#[test]
fn stack_spill_and_reload_preserve_argument_origin() {
    let s = sig(&[
        0x48, 0x83, 0xec, 0x28, 0x48, 0x89, 0x4c, 0x24, 0x20, 0x4c, 0x8b, 0x54, 0x24, 0x20, 0x41,
        0x8b, 0x02, 0x48, 0x83, 0xc4, 0x28, 0xc3,
    ]);
    assert!(s.parameters[0].pointer_read);
    assert_eq!(s.return_type, "int32_t");
}

#[test]
fn entry_stack_alias_recovers_contiguous_stack_only_arguments() {
    let s = sig(&[
        0x48, 0x83, 0xec, 0x68, 0x4c, 0x8d, 0x54, 0x24, 0x68, 0x4d, 0x8b, 0x5a, 0x28, 0x4c, 0x89,
        0x5c, 0x24, 0x20, 0x4d, 0x8b, 0x5a, 0x30, 0x4c, 0x89, 0x5c, 0x24, 0x28, 0x4d, 0x8b, 0x5a,
        0x38, 0x4c, 0x89, 0x5c, 0x24, 0x30, 0x4d, 0x8b, 0x5a, 0x40, 0x4c, 0x89, 0x5c, 0x24, 0x38,
        0x4d, 0x8b, 0x5a, 0x48, 0x4c, 0x89, 0x5c, 0x24, 0x40, 0x4d, 0x8b, 0x5a, 0x50, 0x4c, 0x89,
        0x5c, 0x24, 0x48, 0x4d, 0x8b, 0x5a, 0x58, 0x4c, 0x89, 0x5c, 0x24, 0x50, 0x4d, 0x8b, 0x5a,
        0x60, 0x4c, 0x89, 0x5c, 0x24, 0x58, 0xc3,
    ]);
    assert_eq!(s.parameters.len(), 8);
    assert!(s
        .parameters
        .iter()
        .all(|parameter| parameter.inferred_type == "int64_t"));
    assert_eq!(s.calling_convention, "x64 stack-argument ABI candidate");
    assert!(!s.argument_count_complete);
    assert!(s.prototype.contains("int64_t arg1"));
    assert!(s.prototype.contains("int64_t arg8"));
    assert!(!s.prototype.contains("further arguments unknown"));
}

#[test]
fn overlapping_streams_keep_both_real_paths_and_eight_arguments() {
    let bytes = [
        0x48, 0x83, 0xec, 0x68, 0x4c, 0x8d, 0x54, 0x24, 0x68, 0x4d, 0x8b, 0x5a, 0x28, 0x4c, 0x89,
        0x5c, 0x24, 0x20, 0x4d, 0x8b, 0x5a, 0x30, 0x4c, 0x89, 0x5c, 0x24, 0x28, 0x4d, 0x8b, 0x5a,
        0x38, 0x4c, 0x89, 0x5c, 0x24, 0x30, 0x4d, 0x8b, 0x5a, 0x40, 0x4c, 0x89, 0x5c, 0x24, 0x38,
        0x4d, 0x8b, 0x5a, 0x48, 0x4c, 0x89, 0x5c, 0x24, 0x40, 0x4d, 0x8b, 0x5a, 0x50, 0x4c, 0x89,
        0x5c, 0x24, 0x48, 0x4d, 0x8b, 0x5a, 0x58, 0x4c, 0x89, 0x5c, 0x24, 0x50, 0x4d, 0x8b, 0x5a,
        0x60, 0x4c, 0x89, 0x5c, 0x24, 0x58, 0x41, 0xbb, 0x41, 0xfe, 0x11, 0x9f, 0x41, 0x81, 0xf3,
        0x41, 0xfe, 0x11, 0x9f, 0x45, 0x85, 0xdb, 0x74, 0x04, 0xeb, 0x00, 0x49, 0xbb, 0xe8, 0x0f,
        0x00, 0x00, 0x00, 0xeb, 0x08, 0x3e, 0xb8, 0x22, 0x00, 0x00, 0xc0, 0xeb, 0x00, 0x48, 0x83,
        0xc4, 0x68, 0xc3,
    ];
    let mut rows = decode(&bytes, 64);
    rows.extend(decode_at(&bytes[0x67..0x6e], 64, 0x1067, 0x1067));
    rows.sort_by_key(|row| row.rva);
    let s = infer(&rows, 0x1000, 64, "OverlappingSyscallWrapper", "");
    assert_eq!(s.parameters.len(), 8);
    assert!(s
        .parameters
        .iter()
        .all(|parameter| parameter.inferred_type == "int64_t"));
    assert!(!s.unresolved_flow);
    assert!(rows.iter().any(|row| row.rva == 0x1065));
    assert!(rows.iter().any(|row| row.rva == 0x1067));
}
#[test]
fn fifth_argument_is_entry_stack_relative() {
    let s = sig(&[0x8b, 0x44, 0x24, 0x28, 0xc3]);
    assert_eq!(s.parameters.len(), 5);
    assert_eq!(s.parameters[4].location, "entry-SP+0x28");
    assert_eq!(s.parameters[4].inferred_type, "int32_t");
    assert_eq!(s.parameters[0].inferred_type, "unknown");
}
#[test]
fn float_parameter_and_return() {
    let s = sig(&[0xf3, 0x0f, 0x58, 0xc1, 0xc3]); // addss xmm0,xmm1
    assert_eq!(s.return_type, "float");
    assert_eq!(s.parameters[0].inferred_type, "float");
    assert_eq!(s.parameters[1].inferred_type, "float");
}
#[test]
fn unknown_is_not_void_and_zeroing_is_not_an_argument_read() {
    assert_eq!(sig(&[0xc3]).return_type, "unknown");
    let s = sig(&[0x31, 0xc9, 0x31, 0xc0, 0xc3]);
    assert!(s.parameters.is_empty());
    assert_eq!(s.return_type, "int32_t");
    assert!(!s.prototype.contains("(void)"));
}
#[test]
fn conflicting_return_paths_and_missing_flow_fail_closed() {
    let s = sig(&[0x85, 0xc9, 0x74, 0x06, 0xb8, 1, 0, 0, 0, 0xc3, 0xc3]);
    assert_eq!(s.return_type, "unknown");
    let s = sig(&[0xb8, 1, 0, 0, 0, 0xeb, 0x7f]);
    assert!(s.unresolved_flow);
    assert_eq!(s.return_type, "unknown");
}
#[test]
fn calls_clobber_return_and_argument_aliases() {
    let s = sig(&[0xb8, 1, 0, 0, 0, 0xe8, 0, 0, 0, 0, 0x8b, 0x01, 0xc3]);
    assert!(s.parameters.is_empty());
    assert_eq!(
        sig(&[0xb8, 1, 0, 0, 0, 0xe8, 0, 0, 0, 0, 0xc3]).return_type,
        "unknown"
    );
}
#[test]
fn unreachable_data_does_not_produce_arguments() {
    assert!(sig(&[0x31, 0xc0, 0xc3, 0x8b, 0x01, 0xc3])
        .parameters
        .is_empty());
}
#[test]
fn pdb_prototype_is_preserved_and_x86_is_not_assumed_stdcall() {
    let rows = decode(&[0x8b, 0x44, 0x24, 4, 0xc3], 32);
    let s = infer(&rows, 0x1000, 32, "test", "long __cdecl(int)");
    assert_eq!(s.prototype, "long __cdecl(int)");
    assert_eq!(s.source, "pdb");
    assert_eq!(s.calling_convention, "x86 convention unresolved");
    assert_eq!(s.parameters[0].inferred_type, "int32_t");
}
#[test]
fn overlap_is_reported_and_ordinary_branch_is_not() {
    use crate::analysis::reconstruction::decode_conflicts::inspect;
    let rows = decode(&[0xb8, 0x90, 0x90, 0x90, 0x90, 0xeb, 0xfa], 64);
    let report = inspect(&rows, 64);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].target_rva, 0x1001);
    assert_eq!(report.findings[0].alternative_text, "nop");
    assert!(inspect(&decode(&[0x90, 0xeb, 0xfd], 64), 64)
        .findings
        .is_empty());
}
#[test]
fn instruction_budget_is_explicit() {
    let mut bytes = vec![0x90; MAX_INSTRUCTIONS + 1];
    bytes.push(0xc3);
    let s = sig(&bytes);
    assert!(s.analysis_truncated);
    assert_eq!(s.return_type, "unknown");
}

#[test]
fn lea_arithmetic_width_and_address_return_are_distinct() {
    let s = sig(&[0x8d, 0x04, 0x11, 0xc3]); // lea eax,[rcx+rdx]
    assert_eq!(s.return_type, "int32_t");
    assert_eq!(s.parameters[0].inferred_type, "int32_t");
    assert_eq!(s.parameters[1].inferred_type, "int32_t");
    assert_eq!(
        sig(&[0x48, 0x8d, 0x05, 0, 0, 0, 0, 0xc3]).return_type,
        "void *"
    );
}
#[test]
fn extended_index_keeps_original_argument_width() {
    let s = sig(&[0x48, 0x63, 0xc2, 0x8b, 0x04, 0x81, 0xc3]);
    assert_eq!(s.parameters[0].inferred_type, "const void *");
    assert_eq!(s.parameters[1].inferred_type, "int32_t");
}

#[test]
fn conditional_write_does_not_prove_a_return_definition() {
    assert_eq!(sig(&[0x0f, 0x44, 0xc2, 0xc3]).return_type, "unknown"); // cmove eax,edx
}
#[test]
fn partial_spill_cannot_prove_a_full_pointer_alias() {
    let s = sig(&[
        0x88, 0x4c, 0x24, 0x08, 0x48, 0x8b, 0x44, 0x24, 0x08, 0x8b, 0x00, 0xc3,
    ]);
    assert!(!s.parameters[0].pointer_read);
}
