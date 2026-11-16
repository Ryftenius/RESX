; Public, inert x64 PE fixture for overlapping instruction decoding.
; Build instructions are in README.md in this directory.
option casemap:none

.code
main proc
    xor eax, eax
    ret
main endp

OverlapProbe proc
    ; This zero makes the branch into the middle of the carrier predictable.
    db 045h,031h,0dbh             ; xor r11d, r11d
    db 045h,085h,0dbh             ; test r11d, r11d
    db 074h,004h                   ; je carrier+2
    db 0ebh,000h                   ; jmp carrier
carrier:
    ; Linear stream: mov r11, 9f08eb0000000fe8h.
    ; Branch stream at carrier+2: call HiddenTarget; jmp safe_return.
    db 049h,0bbh,0e8h,00fh,000h,000h,000h,0ebh,008h,09fh
    db 0b8h,022h,000h,000h,0c0h ; decoy: mov eax, STATUS_ACCESS_DENIED
    db 0ebh,000h                   ; jmp safe_return
safe_return:
    ret
OverlapProbe endp

    db 090h,090h,090h,090h       ; keep the hidden call target at +0x0f
HiddenTarget proc
    xor eax, eax                   ; benign callee, no syscall or external API
    ret
HiddenTarget endp

end
