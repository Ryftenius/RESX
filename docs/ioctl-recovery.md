# IOCTL recovery evidence

`ioctl IMAGE --verbose` reports CTL_CODE fields, request comparisons, validated code/handler tables, API arguments, and conditional input/output length guards. JSON includes the supporting RVAs and explicit coverage limits.

The method and access fields come from the IOCTL number. They do not establish runtime access rights, buffer sizes, or a successful request. The device type is shown separately from the function number.

## Buffer lengths

Request length guards follow `IO_STACK_LOCATION.Parameters.DeviceIoControl.InputBufferLength` and `OutputBufferLength` through registers, local spills, selected code paths, and bounded direct helpers. A guard is emitted only when the other branch has a short, direct path to a size-related failing NTSTATUS return or IRP status store. The report retains the comparison, branch, and failure RVAs and status.

For the locally inspected Windows 10.0.26100.9711 dxgkrnl.sys:

| Code | Observed input guard | Observed output guard |
| --- | --- | --- |
| 0x00234003 | == 16 bytes | == 8 bytes |
| 0x0023E057 | >= 832 bytes | >= 832 bytes |
| 0x0023E05B | >= 528 bytes | >= 528 bytes |
| 0x0023E05F | >= 48 bytes | >= 48 bytes |
| 0x0023E067 | >= 616 bytes | >= 616 bytes |

These are static observations for that binary, not portable definitions. Multiple guards can come from different conditional paths or helper variants; they must not be combined into one unconditional contract. `?` means unknown, not zero or no buffer. Buffer field layouts, variable-length formulas, required privileges, complete success conditions, and actual returned byte counts are not recovered by this pass.

## Limits and controls

Request analysis is rooted in recovered registrations, not arbitrary CTL_CODE-shaped constants. It is bounded to 64 roots, 8,192 instructions per root, 131,072 dispatch instructions total, two direct-helper levels, and 256 validated table slots. Length failure probes use at most 48 instructions per edge and 16,384 instructions total. Unknown branches, indirect handlers, dynamic registration, and analysis truncation can leave results incomplete. Checks before a particular code is selected are not assigned to that code. Empty output does not prove that no IOCTLs exist.

Validation covers dxgkrnl.sys, beep.sys, afd.sys, disk.sys, and null.sys, exact AFD code/handler mappings, local WDK definitions, API-call fixtures, and negative controls. Static image mutations remove request/length provenance, corrupt table entries, or replace size errors with success; unsupported results must disappear. Synthetic tests cover stack spills, partial overwrites, arithmetic switch chains, false paths, and analysis budgets. Drivers are inspected on disk, not loaded or sent requests.

KMDF callback registration recovery is not implemented in this RESX pass.
