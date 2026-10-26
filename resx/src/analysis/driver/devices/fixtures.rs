use crate::formats::pe::{read_imports, PeFile, PeSection};
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

fn put(raw: &mut [u8], rva: usize, bytes: &[u8]) {
    let offset = rva - 0x1000 + 0x200;
    raw[offset..offset + bytes.len()].copy_from_slice(bytes);
}
fn unicode(raw: &mut [u8], header: usize, body: usize, value: &str) {
    let bytes: Vec<_> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
    put(raw, header, &(bytes.len() as u16).to_le_bytes());
    put(raw, header + 2, &((bytes.len() + 2) as u16).to_le_bytes());
    put(
        raw,
        header + 8,
        &(0x140000000u64 + body as u64).to_le_bytes(),
    );
    put(raw, body, &bytes);
}
fn call(code: &mut Vec<u8>, slot: u32) {
    let next = 0x1000 + code.len() as u32 + 6;
    code.extend([0xff, 0x15]);
    code.extend(slot.wrapping_sub(next).to_le_bytes());
}
fn fixture(provider: &str, unknown_init: bool, corrupt_sddl: bool) -> super::super::DriverReport {
    let (mut pe, mut raw) = image(&[]);
    pe.data_dirs[1] = (0x2000, 40);
    pe.data_dirs[3] = (0x2380, 12);
    put(
        &mut raw,
        0x2380,
        &[0x00, 0x10, 0, 0, 0x00, 0x11, 0, 0, 0xa0, 0x23, 0, 0],
    );
    put(&mut raw, 0x23a0, &[1, 0, 0, 0]);
    put(&mut raw, 0x2000, &0x2080u32.to_le_bytes());
    put(&mut raw, 0x200c, &0x2040u32.to_le_bytes());
    put(&mut raw, 0x2010, &0x20c0u32.to_le_bytes());
    put(&mut raw, 0x2040, provider.as_bytes());
    for (i, name) in [
        if unknown_init {
            "UnknownUnicodeInitializer"
        } else {
            "RtlInitUnicodeString"
        },
        "IoCreateDeviceSecure",
        "IoCreateSymbolicLink",
    ]
    .iter()
    .enumerate()
    {
        let hint = 0x2100 + i * 0x30;
        put(&mut raw, 0x2080 + i * 8, &(hint as u64).to_le_bytes());
        put(&mut raw, 0x20c0 + i * 8, &(hint as u64).to_le_bytes());
        put(&mut raw, hint + 2, name.as_bytes());
    }
    unicode(&mut raw, 0x2200, 0x2280, "\\Device\\Fixture");
    unicode(&mut raw, 0x2210, 0x22c0, "D:P(A;;GA;;;SY)(A;;GR;;;BU)");
    unicode(&mut raw, 0x2220, 0x2340, "\\DosDevices\\Fixture");
    if corrupt_sddl {
        put(&mut raw, 0x2210, &0xffffu16.to_le_bytes());
    }
    let mut code = vec![0x53, 0x48, 0x83, 0xec, 0x70, 0x48, 0x89, 0xcb]; // save driver in RBX
    code.extend([0x48, 0x8d, 0x4c, 0x24, 0x50, 0x48, 0xba]);
    code.extend(0x140002280u64.to_le_bytes());
    call(&mut code, 0x20c0); // construct local UNICODE_STRING
    code.extend([0x48, 0x89, 0xd9, 0x31, 0xd2, 0x4c, 0x8d, 0x44, 0x24, 0x50]);
    code.extend([0x41, 0xb9, 0x22, 0, 0, 0]); // FILE_DEVICE_UNKNOWN
    code.extend([
        0xc7, 0x44, 0x24, 0x20, 0, 1, 0, 0, 0xc7, 0x44, 0x24, 0x28, 0, 0, 0, 0,
    ]);
    code.extend([0x48, 0xb8]);
    code.extend(0x140002210u64.to_le_bytes());
    code.extend([0x48, 0x89, 0x44, 0x24, 0x30]);
    code.extend([
        0x48, 0xc7, 0x44, 0x24, 0x38, 0, 0, 0, 0, 0x48, 0x8d, 0x44, 0x24, 0x68, 0x48, 0x89, 0x44,
        0x24, 0x40,
    ]);
    call(&mut code, 0x20c8);
    code.extend([0x48, 0xb9]);
    code.extend(0x140002220u64.to_le_bytes());
    code.extend([0x48, 0x8d, 0x54, 0x24, 0x50]);
    call(&mut code, 0x20d0);
    code.extend([0x48, 0x83, 0xc4, 0x70, 0x5b, 0xc3]);
    put(&mut raw, 0x1000, &code);
    super::super::analyze_driver("fixture.sys", &pe, &raw, &read_imports(&pe, &raw))
}
#[test]
fn constructors_recover_counted_names_links_sddl_and_driver_binding() {
    let report = fixture("ntoskrnl.exe", false, false);
    let endpoints = report.ioctl.devices.endpoints;
    assert_eq!(endpoints.len(), 1);
    let endpoint = &endpoints[0];
    assert_eq!(endpoint.device_name.as_deref(), Some("\\Device\\Fixture"));
    assert_eq!(
        endpoint.default_sddl.as_deref(),
        Some("D:P(A;;GA;;;SY)(A;;GR;;;BU)")
    );
    assert_eq!(endpoint.aliases, ["\\DosDevices\\Fixture"]);
    assert_eq!(endpoint.secure_open, Some(true));
    assert!(endpoint.driver_entry_object);
}
#[test]
fn unrelated_strings_wrong_provider_and_unknown_initializer_do_not_establish_endpoints() {
    assert!(fixture("untrusted.dll", false, false)
        .ioctl
        .devices
        .endpoints
        .is_empty());
    let report = fixture("ntoskrnl.exe", true, false);
    assert!(report.ioctl.devices.endpoints[0].device_name.is_none());
    assert!(report.ioctl.devices.endpoints[0].aliases.is_empty());
    let report = fixture("ntoskrnl.exe", false, true);
    assert!(report.ioctl.devices.endpoints[0].default_sddl.is_none());
}
