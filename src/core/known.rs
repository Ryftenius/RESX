pub fn describe_known_address(addr: u64) -> Option<String> {
    describe_kuser_shared_data(addr)
}

fn describe_kuser_shared_data(addr: u64) -> Option<String> {
    const BASE: u64 = 0x0000_0000_7FFE_0000;
    const SIZE: u64 = 0x1000;
    if !(BASE..BASE + SIZE).contains(&addr) {
        return None;
    }

    let off = addr - BASE;
    let name = match off {
        0x000 => "TickCountLowDeprecated",
        0x004 => "TickCountMultiplier",
        0x008 => "InterruptTime",
        0x014 => "SystemTime",
        0x020 => "TimeZoneBias",
        0x030 => "NtSystemRoot",
        0x238 => "MaxStackTraceDepth",
        0x23C => "CryptoExponent",
        0x240 => "TimeZoneId",
        0x244 => "LargePageMinimum",
        0x248 => "AitSamplingValue",
        0x24C => "AppCompatFlag",
        0x250 => "RNGSeedVersion",
        0x258 => "GlobalValidationRunlevel",
        0x25C => "TimeZoneBiasStamp",
        0x260 => "NtBuildNumber",
        0x264 => "NtProductType",
        0x268 => "ProductTypeIsValid",
        0x26A => "NativeProcessorArchitecture",
        0x26C => "NtMajorVersion",
        0x270 => "NtMinorVersion",
        0x274 => "ProcessorFeatures",
        0x2BC => "TimeSlip",
        0x2C0 => "AlternativeArchitecture",
        0x2C8 => "SystemExpirationDate",
        0x2D4 => "SuiteMask",
        0x2D5 => "MitigationPolicies",
        0x2F0 => "SharedDataFlags",
        0x2F8 => "TestRetInstruction",
        0x308 => "SystemCall",
        0x318 => "SystemCallPad",
        _ => return Some(format!("KUSER_SHARED_DATA+0x{:X}", off)),
    };

    Some(format!("KUSER_SHARED_DATA.{}", name))
}
