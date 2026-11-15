# IOCTL device and security evidence

`resx ioctl DRIVER.sys` and `resx driver DRIVER.sys` show, per IOCTL:

- decoded method and access bits
- recovered input/output length guards
- external and internal dispatch channels
- candidate device IDs
- the RVAs where the code is checked

`--verbose` adds dispatch roots and how each result was recovered. `--json` keeps the
full structured records. RIVA takes the same options.

```powershell
resx ioctl C:\Windows\System32\drivers\beep.sys --verbose
resx ioctl C:\Windows\System32\drivers\null.sys --device-security '\Device\Null'
resx ioctl C:\Windows\System32\drivers\null.sys --device-security '\\.\NUL' --json
```

## Static Device Declarations

A device declaration is only reported when the arguments to one of these are resolved:

- `IoCreateDevice`
- `IoCreateDeviceSecure` / `WdmlibIoCreateDeviceSecure`
- the symbolic-link creation APIs

Counted Unicode strings can be immutable globals, or caller locals initialized by
`RtlInitUnicodeString`. A string that's merely nearby, an unknown initializer, or a
malformed length doesn't count as a device name or SDDL.

Each declaration includes the RVA where it's created, and whether the driver-object
argument traces back to the one passed to `DriverEntry`.

## Device Candidates

The device IDs on an IOCTL row are the devices sharing that recovered `DRIVER_OBJECT`.
Several devices often share one dispatch routine, so a candidate isn't necessarily
the device that handles that specific code. It also doesn't tell you the device was
actually created, which driver is loaded right now, its `DEVICE_OBJECT` address, or what
else is attached to the stack.

Some things can't be resolved statically: dynamic PnP/KMDF device names, and security
set through the registry or an INF.

`FILE_DEVICE_SECURE_OPEN` is about how namespace access is checked. It doesn't mean the
DACL is permissive.

## Live Lookup: `--device-security`

`--device-security PATH` queries one local endpoint, the one you name. It resolves the
object name (and the DOS alias where there is one), opens it, and reads the
owner/group/DACL SDDL from the handle.

It never loads a driver and never sends an IOCTL. Opening the device *does* run the
driver's create/close path though, so this isn't a passive read.

The worker gets a 15-second deadline and a 256 KiB output budget. UNC and known
redirector paths are rejected.

## Reading The Results

| Evidence | What it is |
| --- | --- |
| **Declared SDDL** | The default passed to the constructor. Registry policy can override it. |
| **Observed SDDL** | What the security query on the opened endpoint returned. It's not a direct read of the kernel `DEVICE_OBJECT`. Audit SACLs and mandatory labels aren't queried. |
| **Opened / open failed** | Real open attempts with a non-elevated token at medium integrity or lower, for zero, read, write and read+write access. |
| **DACL allows / denies** | The fallback when Windows only allows identification: an `AccessCheck` with the real linked token. This doesn't test an actual open, mandatory integrity, or the driver's own create/dispatch checks. Zero access stays unknown in this mode. |

Text output summarizes the token, SDDL and access probes without the diagnostic
tables. The `User-access test token` label refers to the non-elevated token used for
the access test. It isn't the token used for the SDDL lookup.

`--verbose` adds numeric errors, where each descriptor came from, and the detailed
limitations. `--json` keeps everything.

A few things to keep in mind:

- Access denied doesn't mean running elevated will fix it.
- No suitable token, denied metadata access, unknown device associations and
  unsupported queries are reported as unknown.
- An internal-device-control route isn't reachable through a plain user
  `DeviceIoControl`.
- A successful open doesn't mean the driver will accept any particular IOCTL.
- A static name match doesn't prove the loaded driver is the binary you analyzed.

## JSON

New fields: `devices`, `live_security`, and per-code `request_channels`,
`device_candidates` and `user_accessibility`. The probe fields `opened` and
`dacl_allowed` are nullable, so you can tell a real open result apart from a DACL
evaluation.
