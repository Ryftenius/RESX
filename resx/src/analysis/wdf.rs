#[derive(Debug, Clone, Copy)]
pub struct WdfFunction {
    pub name: &'static str,
    pub index: u32,
}

impl WdfFunction {
    pub fn offset(self, ptr_size: u32) -> u64 {
        self.index as u64 * ptr_size as u64
    }
}

const WDF_FUNCTIONS: &[WdfFunction] = &[
    WdfFunction {
        name: "WdfControlDeviceInitAllocate",
        index: 25,
    },
    WdfFunction {
        name: "WdfControlDeviceInitSetShutdownNotification",
        index: 26,
    },
    WdfFunction {
        name: "WdfControlFinishInitializing",
        index: 27,
    },
    WdfFunction {
        name: "WdfDeviceInitFree",
        index: 54,
    },
    WdfFunction {
        name: "WdfDeviceInitSetPnpPowerEventCallbacks",
        index: 55,
    },
    WdfFunction {
        name: "WdfDeviceInitSetPowerPolicyEventCallbacks",
        index: 56,
    },
    WdfFunction {
        name: "WdfDeviceInitSetIoType",
        index: 61,
    },
    WdfFunction {
        name: "WdfDeviceInitSetExclusive",
        index: 62,
    },
    WdfFunction {
        name: "WdfDeviceInitSetDeviceType",
        index: 66,
    },
    WdfFunction {
        name: "WdfDeviceInitAssignName",
        index: 67,
    },
    WdfFunction {
        name: "WdfDeviceInitAssignSDDLString",
        index: 68,
    },
    WdfFunction {
        name: "WdfDeviceInitSetCharacteristics",
        index: 70,
    },
    WdfFunction {
        name: "WdfDeviceInitSetFileObjectConfig",
        index: 71,
    },
    WdfFunction {
        name: "WdfDeviceCreate",
        index: 75,
    },
    WdfFunction {
        name: "WdfDeviceCreateDeviceInterface",
        index: 77,
    },
    WdfFunction {
        name: "WdfDeviceSetDeviceInterfaceState",
        index: 78,
    },
    WdfFunction {
        name: "WdfDeviceRetrieveDeviceInterfaceString",
        index: 79,
    },
    WdfFunction {
        name: "WdfDeviceCreateSymbolicLink",
        index: 80,
    },
    WdfFunction {
        name: "WdfDeviceGetDefaultQueue",
        index: 92,
    },
    WdfFunction {
        name: "WdfDeviceConfigureRequestDispatching",
        index: 93,
    },
    WdfFunction {
        name: "WdfDriverCreate",
        index: 116,
    },
    WdfFunction {
        name: "WdfDriverGetRegistryPath",
        index: 117,
    },
    WdfFunction {
        name: "WdfDriverWdmGetDriverObject",
        index: 118,
    },
    WdfFunction {
        name: "WdfDriverOpenParametersRegistryKey",
        index: 119,
    },
    WdfFunction {
        name: "WdfWdmDriverGetWdfDriverHandle",
        index: 120,
    },
    WdfFunction {
        name: "WdfDriverRetrieveVersionString",
        index: 122,
    },
    WdfFunction {
        name: "WdfDriverIsVersionAvailable",
        index: 123,
    },
    WdfFunction {
        name: "WdfInterruptCreate",
        index: 141,
    },
    WdfFunction {
        name: "WdfInterruptQueueDpcForIsr",
        index: 142,
    },
    WdfFunction {
        name: "WdfInterruptSynchronize",
        index: 143,
    },
    WdfFunction {
        name: "WdfInterruptAcquireLock",
        index: 144,
    },
    WdfFunction {
        name: "WdfInterruptReleaseLock",
        index: 145,
    },
    WdfFunction {
        name: "WdfInterruptEnable",
        index: 146,
    },
    WdfFunction {
        name: "WdfInterruptDisable",
        index: 147,
    },
    WdfFunction {
        name: "WdfInterruptWdmGetInterrupt",
        index: 148,
    },
    WdfFunction {
        name: "WdfInterruptGetInfo",
        index: 149,
    },
    WdfFunction {
        name: "WdfInterruptSetPolicy",
        index: 150,
    },
    WdfFunction {
        name: "WdfInterruptGetDevice",
        index: 151,
    },
    WdfFunction {
        name: "WdfIoQueueCreate",
        index: 152,
    },
    WdfFunction {
        name: "WdfIoQueueGetState",
        index: 153,
    },
    WdfFunction {
        name: "WdfIoQueueStart",
        index: 154,
    },
    WdfFunction {
        name: "WdfIoQueueStop",
        index: 155,
    },
    WdfFunction {
        name: "WdfIoQueueStopSynchronously",
        index: 156,
    },
    WdfFunction {
        name: "WdfIoQueueGetDevice",
        index: 157,
    },
    WdfFunction {
        name: "WdfIoQueueRetrieveNextRequest",
        index: 158,
    },
    WdfFunction {
        name: "WdfIoQueueRetrieveRequestByFileObject",
        index: 159,
    },
    WdfFunction {
        name: "WdfIoQueueFindRequest",
        index: 160,
    },
    WdfFunction {
        name: "WdfIoQueueRetrieveFoundRequest",
        index: 161,
    },
    WdfFunction {
        name: "WdfIoQueueDrainSynchronously",
        index: 162,
    },
    WdfFunction {
        name: "WdfIoQueueDrain",
        index: 163,
    },
    WdfFunction {
        name: "WdfIoQueuePurgeSynchronously",
        index: 164,
    },
    WdfFunction {
        name: "WdfIoQueuePurge",
        index: 165,
    },
    WdfFunction {
        name: "WdfIoQueueReadyNotify",
        index: 166,
    },
    WdfFunction {
        name: "WdfRequestCreate",
        index: 211,
    },
    WdfFunction {
        name: "WdfRequestCreateFromIrp",
        index: 212,
    },
    WdfFunction {
        name: "WdfRequestReuse",
        index: 213,
    },
    WdfFunction {
        name: "WdfRequestChangeTarget",
        index: 214,
    },
    WdfFunction {
        name: "WdfRequestFormatRequestUsingCurrentType",
        index: 215,
    },
    WdfFunction {
        name: "WdfRequestWdmFormatUsingStackLocation",
        index: 216,
    },
    WdfFunction {
        name: "WdfRequestSend",
        index: 217,
    },
    WdfFunction {
        name: "WdfRequestGetStatus",
        index: 218,
    },
    WdfFunction {
        name: "WdfRequestMarkCancelable",
        index: 219,
    },
    WdfFunction {
        name: "WdfRequestUnmarkCancelable",
        index: 220,
    },
    WdfFunction {
        name: "WdfRequestIsCanceled",
        index: 221,
    },
    WdfFunction {
        name: "WdfRequestCancelSentRequest",
        index: 222,
    },
    WdfFunction {
        name: "WdfRequestIsFrom32BitProcess",
        index: 223,
    },
    WdfFunction {
        name: "WdfRequestSetCompletionRoutine",
        index: 224,
    },
    WdfFunction {
        name: "WdfRequestGetCompletionParams",
        index: 225,
    },
    WdfFunction {
        name: "WdfRequestAllocateTimer",
        index: 226,
    },
    WdfFunction {
        name: "WdfRequestComplete",
        index: 227,
    },
    WdfFunction {
        name: "WdfRequestCompleteWithPriorityBoost",
        index: 228,
    },
    WdfFunction {
        name: "WdfRequestCompleteWithInformation",
        index: 229,
    },
    WdfFunction {
        name: "WdfRequestGetParameters",
        index: 230,
    },
    WdfFunction {
        name: "WdfRequestRetrieveInputMemory",
        index: 231,
    },
    WdfFunction {
        name: "WdfRequestRetrieveOutputMemory",
        index: 232,
    },
    WdfFunction {
        name: "WdfRequestRetrieveInputBuffer",
        index: 233,
    },
    WdfFunction {
        name: "WdfRequestRetrieveOutputBuffer",
        index: 234,
    },
    WdfFunction {
        name: "WdfRequestRetrieveInputWdmMdl",
        index: 235,
    },
    WdfFunction {
        name: "WdfRequestRetrieveOutputWdmMdl",
        index: 236,
    },
    WdfFunction {
        name: "WdfRequestRetrieveUnsafeUserInputBuffer",
        index: 237,
    },
    WdfFunction {
        name: "WdfRequestRetrieveUnsafeUserOutputBuffer",
        index: 238,
    },
    WdfFunction {
        name: "WdfRequestSetInformation",
        index: 239,
    },
    WdfFunction {
        name: "WdfRequestGetInformation",
        index: 240,
    },
];

pub fn function_from_offset(offset: u64, ptr_size: u32) -> Option<WdfFunction> {
    if ptr_size == 0 || !offset.is_multiple_of(ptr_size as u64) {
        return None;
    }
    let index = u32::try_from(offset / ptr_size as u64).ok()?;
    WDF_FUNCTIONS
        .iter()
        .copied()
        .find(|func| func.index == index)
}

pub fn function_by_name(name: &str) -> Option<WdfFunction> {
    let want = normalize_name(name);
    WDF_FUNCTIONS
        .iter()
        .copied()
        .find(|func| normalize_name(func.name) == want)
}

pub fn is_wdf_table_symbol(name: &str) -> bool {
    let tail = name.rsplit('!').next().unwrap_or(name);
    tail.starts_with("WdfFunctions_") || tail == "WdfFunctions"
}

fn normalize_name(name: &str) -> String {
    let tail = name.rsplit('!').next().unwrap_or(name);
    let trimmed = tail.trim_start_matches('_');
    let core = match trimmed.rsplit_once('@') {
        Some((base, suffix)) if suffix.chars().all(|ch| ch.is_ascii_digit()) => base,
        _ => trimmed,
    };
    core.to_ascii_lowercase()
}
