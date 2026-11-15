# IOCTL recovery evidence

`ioctl IMAGE --verbose` reports CTL_CODE fields, request comparisons, validated
code/handler tables, API arguments, and conditional input/output length guards. JSON
includes the RVAs behind each result and the coverage limits.

Method and access are decoded straight from the IOCTL number. They tell you how the
code is *defined*, not what access a caller really needs or whether a request
succeeds. Device type and function number are shown separately.

## Buffer Lengths

Length guards are found by following
`IO_STACK_LOCATION.Parameters.DeviceIoControl.InputBufferLength` and
`OutputBufferLength` through registers, local spills, the relevant code paths, and
direct helpers (bounded).

A guard is only reported when the other side of the branch has a short, direct path to
a size-related failure, either a failing NTSTATUS return or an IRP status store. The
report keeps the comparison, branch and failure RVAs plus the status.

For the local Windows 10.0.26100.9711 `dxgkrnl.sys`:

| Code | Input guard | Output guard |
| --- | --- | --- |
| 0x00234003 | == 16 bytes | == 8 bytes |
| 0x0023E057 | >= 832 bytes | >= 832 bytes |
| 0x0023E05B | >= 528 bytes | >= 528 bytes |
| 0x0023E05F | >= 48 bytes | >= 48 bytes |
| 0x0023E067 | >= 616 bytes | >= 616 bytes |

Those numbers are for that exact build. Don't treat them as definitions for other
versions.

- One code can have several guards on different paths or helpers. Don't merge them into
  one rule.
- `?` means unknown. It doesn't mean zero or no buffer.
- This pass doesn't recover buffer layouts, variable-length formulas, required
  privileges, full success conditions, or how many bytes actually come back.

## Limits

Analysis starts from recovered registrations, not from any constant that happens to look
like a CTL_CODE.

| Budget | Limit |
| --- | --- |
| Dispatch roots | 64 |
| Instructions per root | 8,192 |
| Dispatch instructions total | 131,072 |
| Direct-helper depth | 2 levels |
| Validated table slots | 256 |
| Length-failure probe per edge | 48 instructions |
| Length-failure probes total | 16,384 instructions |

Unknown branches, indirect handlers, dynamic registration and hitting a budget can all
leave results incomplete. Checks that happen before a specific code is selected aren't
attributed to that code. No output doesn't mean the driver has no IOCTLs.

KMDF callback registration isn't recovered yet.

## Validation

Tested against `dxgkrnl.sys`, `beep.sys`, `afd.sys`, `disk.sys` and `null.sys`, exact AFD
code/handler mappings, the local WDK definitions, API-call fixtures and negative
controls.

Mutation tests modify the images to strip request/length provenance, corrupt table
entries, or swap size errors for success. When the evidence is gone, the result has to
disappear too. Synthetic tests cover stack spills, partial overwrites, arithmetic switch
chains, false paths and budget exhaustion.

Drivers are only ever read from disk. Nothing is loaded and no requests are sent.
