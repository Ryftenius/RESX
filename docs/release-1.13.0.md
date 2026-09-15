# RESX 1.13.0

RESX 1.13.0 adds bounded hypervisor and driver-capability recovery to `driver`.
The report identifies AMD SVM and Intel VMX instruction families, VM-entry and
control-state operations, virtualization-specific CPUID/MSR setup, Intel EPT and
VPID invalidation, and an AMD VMCB signature that requires matching `NpEnable`,
guest ASID, and `NCr3` fields before reporting configured nested paging.

Direct `VMCALL`, `VMMCALL`, and `VMGEXIT` stubs combined with Windows Hvl/WinHv
imports are classified as hypervisor interface consumers. They are not reported
as implementations without VM-entry or setup evidence. Named imported kernel APIs
are grouped into capabilities such as physical-memory mapping, MDL access, DMA,
cross-process access, monitoring, network filtering, and device-control requests.
These groups describe the imported API surface; execution remains unobserved.

The local validation set contains JSON and text reports for twelve System32
drivers and all four signed Blackbird PE images. Blackbird's AMD hypervisor was
identified from `VMRUN`, `VMLOAD`, `VMSAVE`, `STGI`, SVM CPUID/MSRs, and the
three-field NPT signature. Ordinary disk, networking, PSP, and utility-driver
controls did not receive a hypervisor implementation classification.

Text tables now read the visible Windows console width and distribute available
columns according to the actual content. Fixed identifiers such as RVAs and owner
names are preserved before long prose columns expand. Narrow consoles wrap within
their boundary; wide consoles give long API and evidence columns the remaining
horizontal space. File output uses a stable 120-column layout.

Command completion timing is silent by default. `--time` prints the elapsed time
on stderr, while `--quiet` suppresses it.

Human-facing version, help, and verbose output now uses the full product identity:

```text
Ryftenius (R) RESX Reverse Engineering Suite Extended, Version 1.13.0
Copyright (C) Ryftenius.
```
