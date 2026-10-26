//! Syscall service numbers in native stubs.
//!
//! An x64 stub loads the service number into eax and traps (`syscall`, or
//! `int 0x2e` on the alternate path). A WoW64 stub loads it the same way and calls
//! the dispatcher through edx. A kernel Zw* stub builds an interrupt frame (cli,
//! pushfq), loads eax and jumps to KiServiceInternal. Numbers from 0x1000 index the
//! win32k table.

use iced_x86::{
    Instruction as Decoded, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register,
};

use super::Instruction;

/// Instructions searched after the eax load for the trap or dispatcher call.
const STUB_WINDOW: usize = 6;
/// Instructions searched before the eax load for a kernel Zw* stub's frame setup.
const FRAME_WINDOW: usize = 8;
/// Service numbers are a table bit (0x1000) plus a small index; larger immediates
/// are ordinary constants.
const MAX_SERVICE_NUMBER: u32 = 0x2000;
const WIN32K_TABLE_BASE: u32 = 0x1000;

/// Labels each service-number load in `insns` with its syscall number. Any literal
/// guess already on the immediate (`STATUS_*`, ...) is replaced: the value is an
/// index into the service table, not a status. Safe to run more than once.
pub fn annotate_syscall_numbers(insns: &mut [Instruction]) {
    let mut factory = InstructionInfoFactory::new();
    for index in 0..insns.len() {
        let Some(number) = service_number_load(&insns[index].iced) else {
            continue;
        };
        if insns[index].comment.starts_with("syscall ") {
            continue;
        }
        let kernel_frame =
            builds_kernel_service_frame(&insns[index.saturating_sub(FRAME_WINDOW)..index]);
        if reaches_service_dispatch(&insns[index + 1..], kernel_frame, &mut factory) {
            insns[index].comment = describe(number);
        }
    }
}

fn describe(number: u32) -> String {
    if number >= WIN32K_TABLE_BASE {
        format!(
            "syscall 0x{number:X} (win32k #{})",
            number - WIN32K_TABLE_BASE
        )
    } else {
        format!("syscall 0x{number:X} ({number})")
    }
}

/// `mov eax, imm32` with an immediate in service-number range.
fn service_number_load(instr: &Decoded) -> Option<u32> {
    if instr.mnemonic() != Mnemonic::Mov
        || instr.op_count() != 2
        || instr.op0_kind() != OpKind::Register
        || instr.op0_register() != Register::EAX
        || instr.op1_kind() != OpKind::Immediate32
    {
        return None;
    }
    Some(instr.immediate32()).filter(|number| *number < MAX_SERVICE_NUMBER)
}

/// `cli` then `pushfq`: the interrupt frame a kernel Zw* stub builds by hand.
fn builds_kernel_service_frame(preceding: &[Instruction]) -> bool {
    let cli = preceding
        .iter()
        .position(|insn| insn.iced.mnemonic() == Mnemonic::Cli);
    cli.is_some_and(|cli| {
        preceding[cli..]
            .iter()
            .any(|insn| insn.iced.mnemonic() == Mnemonic::Pushfq)
    })
}

/// True when a trap, a WoW64 `mov edx, imm` + `call edx` dispatch, or a kernel
/// stub's jump to KiServiceInternal follows before eax is overwritten or control
/// leaves the stub.
fn reaches_service_dispatch(
    following: &[Instruction],
    kernel_frame: bool,
    factory: &mut InstructionInfoFactory,
) -> bool {
    let mut edx_holds_dispatcher = false;
    for insn in following.iter().take(STUB_WINDOW) {
        let instr = &insn.iced;
        match instr.mnemonic() {
            Mnemonic::Syscall | Mnemonic::Sysenter => return true,
            Mnemonic::Int if instr.immediate8() == 0x2E => return true,
            Mnemonic::Call => {
                let through_edx =
                    instr.op0_kind() == OpKind::Register && instr.op0_register() == Register::EDX;
                return through_edx && edx_holds_dispatcher;
            }
            Mnemonic::Jmp => {
                return kernel_frame
                    || insn.operands.contains("KiServiceInternal")
                    || insn.comment.contains("KiServiceInternal");
            }
            Mnemonic::Ret => return false,
            _ => {}
        }
        if instr.mnemonic() == Mnemonic::Mov
            && instr.op0_kind() == OpKind::Register
            && instr.op0_register() == Register::EDX
            && instr.op1_kind() == OpKind::Immediate32
        {
            edx_holds_dispatcher = true;
        } else if writes_register(factory, instr, Register::EDX) {
            edx_holds_dispatcher = false;
        }
        if writes_register(factory, instr, Register::EAX) {
            return false;
        }
    }
    false
}

fn writes_register(
    factory: &mut InstructionInfoFactory,
    instr: &Decoded,
    register: Register,
) -> bool {
    factory.info(instr).used_registers().iter().any(|used| {
        used.register().full_register() == register.full_register()
            && matches!(
                used.access(),
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            )
    })
}

#[cfg(test)]
mod tests {
    use super::{annotate_syscall_numbers, Instruction};
    use iced_x86::{Decoder, DecoderOptions};

    fn decode(bitness: u32, bytes: &[u8], comments: &[(usize, &str)]) -> Vec<Instruction> {
        let mut decoder = Decoder::with_ip(bitness, bytes, 0x1000, DecoderOptions::NONE);
        let mut out = Vec::new();
        while decoder.can_decode() {
            let iced = decoder.decode();
            out.push(Instruction {
                block_start: 0x1000,
                rva: iced.ip() as u32,
                va: iced.ip(),
                file_off: 0,
                bytes: Vec::new(),
                text: String::new(),
                mnemonic: String::new(),
                operands: String::new(),
                iced,
                comment: String::new(),
                is_call: false,
                is_jmp: false,
                is_jcc: false,
                call_target: 0,
            });
        }
        for (index, comment) in comments {
            out[*index].comment = (*comment).to_owned();
        }
        out
    }

    // mov r10, rcx; mov eax, N; test byte ptr [0x7ffe0308], 1; jne +3; syscall; ret; int 0x2e; ret
    fn x64_stub(number: u32) -> Vec<u8> {
        let mut bytes = vec![0x4C, 0x8B, 0xD1, 0xB8];
        bytes.extend(number.to_le_bytes());
        bytes.extend([
            0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01, 0x75, 0x03, 0x0F, 0x05, 0xC3, 0xCD,
            0x2E, 0xC3,
        ]);
        bytes
    }

    #[test]
    fn x64_stub_load_is_labeled_and_replaces_literal_guesses() {
        let mut insns = decode(64, &x64_stub(0x18), &[(1, "STATUS_SUCCESS")]);
        annotate_syscall_numbers(&mut insns);
        assert_eq!(insns[1].comment, "syscall 0x18 (24)");
        annotate_syscall_numbers(&mut insns);
        assert_eq!(insns[1].comment, "syscall 0x18 (24)", "idempotent");
    }

    #[test]
    fn win32k_numbers_name_their_table() {
        let mut insns = decode(64, &x64_stub(0x1004), &[]);
        annotate_syscall_numbers(&mut insns);
        assert_eq!(insns[1].comment, "syscall 0x1004 (win32k #4)");
    }

    #[test]
    fn wow64_stub_dispatches_through_edx() {
        // mov eax, 0x18; mov edx, 0x4b336170; call edx; ret 0x18
        let bytes = [
            0xB8, 0x18, 0x00, 0x00, 0x00, 0xBA, 0x70, 0x61, 0x33, 0x4B, 0xFF, 0xD2, 0xC2, 0x18,
            0x00,
        ];
        let mut insns = decode(32, &bytes, &[]);
        annotate_syscall_numbers(&mut insns);
        assert_eq!(insns[0].comment, "syscall 0x18 (24)");
    }

    #[test]
    fn kernel_zw_stub_jumps_to_the_service_dispatcher() {
        // mov rax, rsp; cli; sub rsp, 0x10; push rax; pushfq; push 0x10; mov eax, 0x18; jmp +0
        let bytes = [
            0x48, 0x8B, 0xC4, 0xFA, 0x48, 0x83, 0xEC, 0x10, 0x50, 0x9C, 0x6A, 0x10, 0xB8, 0x18,
            0x00, 0x00, 0x00, 0xE9, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut insns = decode(64, &bytes, &[]);
        annotate_syscall_numbers(&mut insns);
        assert_eq!(insns[6].comment, "syscall 0x18 (24)");

        // Without the frame, a plain eax load and jump is an ordinary tail call.
        let mut tail = decode(
            64,
            &[0xB8, 0x18, 0x00, 0x00, 0x00, 0xE9, 0x00, 0x00, 0x00, 0x00],
            &[],
        );
        annotate_syscall_numbers(&mut tail);
        assert_eq!(tail[0].comment, "");
    }

    #[test]
    fn ordinary_eax_constants_are_left_alone() {
        // mov eax, 0x18; ret
        let mut returned = decode(64, &[0xB8, 0x18, 0x00, 0x00, 0x00, 0xC3], &[(0, "keep")]);
        annotate_syscall_numbers(&mut returned);
        assert_eq!(returned[0].comment, "keep");

        // mov eax, 0x18; xor eax, eax; syscall
        let mut clobbered = decode(
            64,
            &[0xB8, 0x18, 0x00, 0x00, 0x00, 0x31, 0xC0, 0x0F, 0x05],
            &[],
        );
        annotate_syscall_numbers(&mut clobbered);
        assert_eq!(clobbered[0].comment, "");

        // mov eax, 0x18; call rax  (not a WoW64 dispatch)
        let mut indirect = decode(64, &[0xB8, 0x18, 0x00, 0x00, 0x00, 0xFF, 0xD0], &[]);
        annotate_syscall_numbers(&mut indirect);
        assert_eq!(indirect[0].comment, "");
    }
}
