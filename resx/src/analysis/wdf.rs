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

/// KMDF `WDFFUNCENUM` order: the index of each function in the
/// `WdfFunctions_01xxx` table that KMDF drivers call through. Extracted from the
/// `WdfVersion` table in Wdf01000.sys (KMDF 1.33, 458 entries). KMDF only
/// appends to this table, so earlier 1.x drivers use a prefix of it.
const WDF_FUNCTIONS: &[&str] = &[
    "WdfChildListCreate",
    "WdfChildListGetDevice",
    "WdfChildListRetrievePdo",
    "WdfChildListRetrieveAddressDescription",
    "WdfChildListBeginScan",
    "WdfChildListEndScan",
    "WdfChildListBeginIteration",
    "WdfChildListRetrieveNextDevice",
    "WdfChildListEndIteration",
    "WdfChildListAddOrUpdateChildDescriptionAsPresent",
    "WdfChildListUpdateChildDescriptionAsMissing",
    "WdfChildListUpdateAllChildDescriptionsAsPresent",
    "WdfChildListRequestChildEject",
    "WdfCollectionCreate",
    "WdfCollectionGetCount",
    "WdfCollectionAdd",
    "WdfCollectionRemove",
    "WdfCollectionRemoveItem",
    "WdfCollectionGetItem",
    "WdfCollectionGetFirstItem",
    "WdfCollectionGetLastItem",
    "WdfCommonBufferCreate",
    "WdfCommonBufferGetAlignedVirtualAddress",
    "WdfCommonBufferGetAlignedLogicalAddress",
    "WdfCommonBufferGetLength",
    "WdfControlDeviceInitAllocate",
    "WdfControlDeviceInitSetShutdownNotification",
    "WdfControlFinishInitializing",
    "WdfDeviceGetDeviceState",
    "WdfDeviceSetDeviceState",
    "WdfWdmDeviceGetWdfDeviceHandle",
    "WdfDeviceWdmGetDeviceObject",
    "WdfDeviceWdmGetAttachedDevice",
    "WdfDeviceWdmGetPhysicalDevice",
    "WdfDeviceWdmDispatchPreprocessedIrp",
    "WdfDeviceAddDependentUsageDeviceObject",
    "WdfDeviceAddRemovalRelationsPhysicalDevice",
    "WdfDeviceRemoveRemovalRelationsPhysicalDevice",
    "WdfDeviceClearRemovalRelationsDevices",
    "WdfDeviceGetDriver",
    "WdfDeviceRetrieveDeviceName",
    "WdfDeviceAssignMofResourceName",
    "WdfDeviceGetIoTarget",
    "WdfDeviceGetDevicePnpState",
    "WdfDeviceGetDevicePowerState",
    "WdfDeviceGetDevicePowerPolicyState",
    "WdfDeviceAssignS0IdleSettings",
    "WdfDeviceAssignSxWakeSettings",
    "WdfDeviceOpenRegistryKey",
    "WdfDeviceSetSpecialFileSupport",
    "WdfDeviceSetCharacteristics",
    "WdfDeviceGetCharacteristics",
    "WdfDeviceGetAlignmentRequirement",
    "WdfDeviceSetAlignmentRequirement",
    "WdfDeviceInitFree",
    "WdfDeviceInitSetPnpPowerEventCallbacks",
    "WdfDeviceInitSetPowerPolicyEventCallbacks",
    "WdfDeviceInitSetPowerPolicyOwnership",
    "WdfDeviceInitRegisterPnpStateChangeCallback",
    "WdfDeviceInitRegisterPowerStateChangeCallback",
    "WdfDeviceInitRegisterPowerPolicyStateChangeCallback",
    "WdfDeviceInitSetIoType",
    "WdfDeviceInitSetExclusive",
    "WdfDeviceInitSetPowerNotPageable",
    "WdfDeviceInitSetPowerPageable",
    "WdfDeviceInitSetPowerInrush",
    "WdfDeviceInitSetDeviceType",
    "WdfDeviceInitAssignName",
    "WdfDeviceInitAssignSDDLString",
    "WdfDeviceInitSetDeviceClass",
    "WdfDeviceInitSetCharacteristics",
    "WdfDeviceInitSetFileObjectConfig",
    "WdfDeviceInitSetRequestAttributes",
    "WdfDeviceInitAssignWdmIrpPreprocessCallback",
    "WdfDeviceInitSetIoInCallerContextCallback",
    "WdfDeviceCreate",
    "WdfDeviceSetStaticStopRemove",
    "WdfDeviceCreateDeviceInterface",
    "WdfDeviceSetDeviceInterfaceState",
    "WdfDeviceRetrieveDeviceInterfaceString",
    "WdfDeviceCreateSymbolicLink",
    "WdfDeviceQueryProperty",
    "WdfDeviceAllocAndQueryProperty",
    "WdfDeviceSetPnpCapabilities",
    "WdfDeviceSetPowerCapabilities",
    "WdfDeviceSetBusInformationForChildren",
    "WdfDeviceIndicateWakeStatus",
    "WdfDeviceSetFailed",
    "WdfDeviceStopIdleNoTrack",
    "WdfDeviceResumeIdleNoTrack",
    "WdfDeviceGetFileObject",
    "WdfDeviceEnqueueRequest",
    "WdfDeviceGetDefaultQueue",
    "WdfDeviceConfigureRequestDispatching",
    "WdfDmaEnablerCreate",
    "WdfDmaEnablerGetMaximumLength",
    "WdfDmaEnablerGetMaximumScatterGatherElements",
    "WdfDmaEnablerSetMaximumScatterGatherElements",
    "WdfDmaTransactionCreate",
    "WdfDmaTransactionInitialize",
    "WdfDmaTransactionInitializeUsingRequest",
    "WdfDmaTransactionExecute",
    "WdfDmaTransactionRelease",
    "WdfDmaTransactionDmaCompleted",
    "WdfDmaTransactionDmaCompletedWithLength",
    "WdfDmaTransactionDmaCompletedFinal",
    "WdfDmaTransactionGetBytesTransferred",
    "WdfDmaTransactionSetMaximumLength",
    "WdfDmaTransactionGetRequest",
    "WdfDmaTransactionGetCurrentDmaTransferLength",
    "WdfDmaTransactionGetDevice",
    "WdfDpcCreate",
    "WdfDpcEnqueue",
    "WdfDpcCancel",
    "WdfDpcGetParentObject",
    "WdfDpcWdmGetDpc",
    "WdfDriverCreate",
    "WdfDriverGetRegistryPath",
    "WdfDriverWdmGetDriverObject",
    "WdfDriverOpenParametersRegistryKey",
    "WdfWdmDriverGetWdfDriverHandle",
    "WdfDriverRegisterTraceInfo",
    "WdfDriverRetrieveVersionString",
    "WdfDriverIsVersionAvailable",
    "WdfFdoInitWdmGetPhysicalDevice",
    "WdfFdoInitOpenRegistryKey",
    "WdfFdoInitQueryProperty",
    "WdfFdoInitAllocAndQueryProperty",
    "WdfFdoInitSetEventCallbacks",
    "WdfFdoInitSetFilter",
    "WdfFdoInitSetDefaultChildListConfig",
    "WdfFdoQueryForInterface",
    "WdfFdoGetDefaultChildList",
    "WdfFdoAddStaticChild",
    "WdfFdoLockStaticChildListForIteration",
    "WdfFdoRetrieveNextStaticChild",
    "WdfFdoUnlockStaticChildListFromIteration",
    "WdfFileObjectGetFileName",
    "WdfFileObjectGetFlags",
    "WdfFileObjectGetDevice",
    "WdfFileObjectWdmGetFileObject",
    "WdfInterruptCreate",
    "WdfInterruptQueueDpcForIsr",
    "WdfInterruptSynchronize",
    "WdfInterruptAcquireLock",
    "WdfInterruptReleaseLock",
    "WdfInterruptEnable",
    "WdfInterruptDisable",
    "WdfInterruptWdmGetInterrupt",
    "WdfInterruptGetInfo",
    "WdfInterruptSetPolicy",
    "WdfInterruptGetDevice",
    "WdfIoQueueCreate",
    "WdfIoQueueGetState",
    "WdfIoQueueStart",
    "WdfIoQueueStop",
    "WdfIoQueueStopSynchronously",
    "WdfIoQueueGetDevice",
    "WdfIoQueueRetrieveNextRequest",
    "WdfIoQueueRetrieveRequestByFileObject",
    "WdfIoQueueFindRequest",
    "WdfIoQueueRetrieveFoundRequest",
    "WdfIoQueueDrainSynchronously",
    "WdfIoQueueDrain",
    "WdfIoQueuePurgeSynchronously",
    "WdfIoQueuePurge",
    "WdfIoQueueReadyNotify",
    "WdfIoTargetCreate",
    "WdfIoTargetOpen",
    "WdfIoTargetCloseForQueryRemove",
    "WdfIoTargetClose",
    "WdfIoTargetStart",
    "WdfIoTargetStop",
    "WdfIoTargetGetState",
    "WdfIoTargetGetDevice",
    "WdfIoTargetQueryTargetProperty",
    "WdfIoTargetAllocAndQueryTargetProperty",
    "WdfIoTargetQueryForInterface",
    "WdfIoTargetWdmGetTargetDeviceObject",
    "WdfIoTargetWdmGetTargetPhysicalDevice",
    "WdfIoTargetWdmGetTargetFileObject",
    "WdfIoTargetWdmGetTargetFileHandle",
    "WdfIoTargetSendReadSynchronously",
    "WdfIoTargetFormatRequestForRead",
    "WdfIoTargetSendWriteSynchronously",
    "WdfIoTargetFormatRequestForWrite",
    "WdfIoTargetSendIoctlSynchronously",
    "WdfIoTargetFormatRequestForIoctl",
    "WdfIoTargetSendInternalIoctlSynchronously",
    "WdfIoTargetFormatRequestForInternalIoctl",
    "WdfIoTargetSendInternalIoctlOthersSynchronously",
    "WdfIoTargetFormatRequestForInternalIoctlOthers",
    "WdfMemoryCreate",
    "WdfMemoryCreatePreallocated",
    "WdfMemoryGetBuffer",
    "WdfMemoryAssignBuffer",
    "WdfMemoryCopyToBuffer",
    "WdfMemoryCopyFromBuffer",
    "WdfLookasideListCreate",
    "WdfMemoryCreateFromLookaside",
    "WdfDeviceMiniportCreate",
    "WdfDriverMiniportUnload",
    "WdfObjectGetTypedContextWorker",
    "WdfObjectAllocateContext",
    "WdfObjectContextGetObject",
    "WdfObjectReferenceActual",
    "WdfObjectDereferenceActual",
    "WdfObjectCreate",
    "WdfObjectDelete",
    "WdfObjectQuery",
    "WdfPdoInitAllocate",
    "WdfPdoInitSetEventCallbacks",
    "WdfPdoInitAssignDeviceID",
    "WdfPdoInitAssignInstanceID",
    "WdfPdoInitAddHardwareID",
    "WdfPdoInitAddCompatibleID",
    "WdfPdoInitAddDeviceText",
    "WdfPdoInitSetDefaultLocale",
    "WdfPdoInitAssignRawDevice",
    "WdfPdoMarkMissing",
    "WdfPdoRequestEject",
    "WdfPdoGetParent",
    "WdfPdoRetrieveIdentificationDescription",
    "WdfPdoRetrieveAddressDescription",
    "WdfPdoUpdateAddressDescription",
    "WdfPdoAddEjectionRelationsPhysicalDevice",
    "WdfPdoRemoveEjectionRelationsPhysicalDevice",
    "WdfPdoClearEjectionRelationsDevices",
    "WdfDeviceAddQueryInterface",
    "WdfRegistryOpenKey",
    "WdfRegistryCreateKey",
    "WdfRegistryClose",
    "WdfRegistryWdmGetHandle",
    "WdfRegistryRemoveKey",
    "WdfRegistryRemoveValue",
    "WdfRegistryQueryValue",
    "WdfRegistryQueryMemory",
    "WdfRegistryQueryMultiString",
    "WdfRegistryQueryUnicodeString",
    "WdfRegistryQueryString",
    "WdfRegistryQueryULong",
    "WdfRegistryAssignValue",
    "WdfRegistryAssignMemory",
    "WdfRegistryAssignMultiString",
    "WdfRegistryAssignUnicodeString",
    "WdfRegistryAssignString",
    "WdfRegistryAssignULong",
    "WdfRequestCreate",
    "WdfRequestCreateFromIrp",
    "WdfRequestReuse",
    "WdfRequestChangeTarget",
    "WdfRequestFormatRequestUsingCurrentType",
    "WdfRequestWdmFormatUsingStackLocation",
    "WdfRequestSend",
    "WdfRequestGetStatus",
    "WdfRequestMarkCancelable",
    "WdfRequestUnmarkCancelable",
    "WdfRequestIsCanceled",
    "WdfRequestCancelSentRequest",
    "WdfRequestIsFrom32BitProcess",
    "WdfRequestSetCompletionRoutine",
    "WdfRequestGetCompletionParams",
    "WdfRequestAllocateTimer",
    "WdfRequestComplete",
    "WdfRequestCompleteWithPriorityBoost",
    "WdfRequestCompleteWithInformation",
    "WdfRequestGetParameters",
    "WdfRequestRetrieveInputMemory",
    "WdfRequestRetrieveOutputMemory",
    "WdfRequestRetrieveInputBuffer",
    "WdfRequestRetrieveOutputBuffer",
    "WdfRequestRetrieveInputWdmMdl",
    "WdfRequestRetrieveOutputWdmMdl",
    "WdfRequestRetrieveUnsafeUserInputBuffer",
    "WdfRequestRetrieveUnsafeUserOutputBuffer",
    "WdfRequestSetInformation",
    "WdfRequestGetInformation",
    "WdfRequestGetFileObject",
    "WdfRequestProbeAndLockUserBufferForRead",
    "WdfRequestProbeAndLockUserBufferForWrite",
    "WdfRequestGetRequestorMode",
    "WdfRequestForwardToIoQueue",
    "WdfRequestGetIoQueue",
    "WdfRequestRequeue",
    "WdfRequestStopAcknowledge",
    "WdfRequestWdmGetIrp",
    "WdfIoResourceRequirementsListSetSlotNumber",
    "WdfIoResourceRequirementsListSetInterfaceType",
    "WdfIoResourceRequirementsListAppendIoResList",
    "WdfIoResourceRequirementsListInsertIoResList",
    "WdfIoResourceRequirementsListGetCount",
    "WdfIoResourceRequirementsListGetIoResList",
    "WdfIoResourceRequirementsListRemove",
    "WdfIoResourceRequirementsListRemoveByIoResList",
    "WdfIoResourceListCreate",
    "WdfIoResourceListAppendDescriptor",
    "WdfIoResourceListInsertDescriptor",
    "WdfIoResourceListUpdateDescriptor",
    "WdfIoResourceListGetCount",
    "WdfIoResourceListGetDescriptor",
    "WdfIoResourceListRemove",
    "WdfIoResourceListRemoveByDescriptor",
    "WdfCmResourceListAppendDescriptor",
    "WdfCmResourceListInsertDescriptor",
    "WdfCmResourceListGetCount",
    "WdfCmResourceListGetDescriptor",
    "WdfCmResourceListRemove",
    "WdfCmResourceListRemoveByDescriptor",
    "WdfStringCreate",
    "WdfStringGetUnicodeString",
    "WdfObjectAcquireLock",
    "WdfObjectReleaseLock",
    "WdfWaitLockCreate",
    "WdfWaitLockAcquire",
    "WdfWaitLockRelease",
    "WdfSpinLockCreate",
    "WdfSpinLockAcquire",
    "WdfSpinLockRelease",
    "WdfTimerCreate",
    "WdfTimerStart",
    "WdfTimerStop",
    "WdfTimerGetParentObject",
    "WdfUsbTargetDeviceCreate",
    "WdfUsbTargetDeviceRetrieveInformation",
    "WdfUsbTargetDeviceGetDeviceDescriptor",
    "WdfUsbTargetDeviceRetrieveConfigDescriptor",
    "WdfUsbTargetDeviceQueryString",
    "WdfUsbTargetDeviceAllocAndQueryString",
    "WdfUsbTargetDeviceFormatRequestForString",
    "WdfUsbTargetDeviceGetNumInterfaces",
    "WdfUsbTargetDeviceSelectConfig",
    "WdfUsbTargetDeviceWdmGetConfigurationHandle",
    "WdfUsbTargetDeviceRetrieveCurrentFrameNumber",
    "WdfUsbTargetDeviceSendControlTransferSynchronously",
    "WdfUsbTargetDeviceFormatRequestForControlTransfer",
    "WdfUsbTargetDeviceIsConnectedSynchronous",
    "WdfUsbTargetDeviceResetPortSynchronously",
    "WdfUsbTargetDeviceCyclePortSynchronously",
    "WdfUsbTargetDeviceFormatRequestForCyclePort",
    "WdfUsbTargetDeviceSendUrbSynchronously",
    "WdfUsbTargetDeviceFormatRequestForUrb",
    "WdfUsbTargetPipeGetInformation",
    "WdfUsbTargetPipeIsInEndpoint",
    "WdfUsbTargetPipeIsOutEndpoint",
    "WdfUsbTargetPipeGetType",
    "WdfUsbTargetPipeSetNoMaximumPacketSizeCheck",
    "WdfUsbTargetPipeWriteSynchronously",
    "WdfUsbTargetPipeFormatRequestForWrite",
    "WdfUsbTargetPipeReadSynchronously",
    "WdfUsbTargetPipeFormatRequestForRead",
    "WdfUsbTargetPipeConfigContinuousReader",
    "WdfUsbTargetPipeAbortSynchronously",
    "WdfUsbTargetPipeFormatRequestForAbort",
    "WdfUsbTargetPipeResetSynchronously",
    "WdfUsbTargetPipeFormatRequestForReset",
    "WdfUsbTargetPipeSendUrbSynchronously",
    "WdfUsbTargetPipeFormatRequestForUrb",
    "WdfUsbInterfaceGetInterfaceNumber",
    "WdfUsbInterfaceGetNumEndpoints",
    "WdfUsbInterfaceGetDescriptor",
    "WdfUsbInterfaceSelectSetting",
    "WdfUsbInterfaceGetEndpointInformation",
    "WdfUsbTargetDeviceGetInterface",
    "WdfUsbInterfaceGetConfiguredSettingIndex",
    "WdfUsbInterfaceGetNumConfiguredPipes",
    "WdfUsbInterfaceGetConfiguredPipe",
    "WdfUsbTargetPipeWdmGetPipeHandle",
    "WdfVerifierDbgBreakPoint",
    "WdfVerifierKeBugCheck",
    "WdfWmiProviderCreate",
    "WdfWmiProviderGetDevice",
    "WdfWmiProviderIsEnabled",
    "WdfWmiProviderGetTracingHandle",
    "WdfWmiInstanceCreate",
    "WdfWmiInstanceRegister",
    "WdfWmiInstanceDeregister",
    "WdfWmiInstanceGetDevice",
    "WdfWmiInstanceGetProvider",
    "WdfWmiInstanceFireEvent",
    "WdfWorkItemCreate",
    "WdfWorkItemEnqueue",
    "WdfWorkItemGetParentObject",
    "WdfWorkItemFlush",
    "WdfCommonBufferCreateWithConfig",
    "WdfDmaEnablerGetFragmentLength",
    "WdfDmaEnablerWdmGetDmaAdapter",
    "WdfUsbInterfaceGetNumSettings",
    "WdfDeviceRemoveDependentUsageDeviceObject",
    "WdfDeviceGetSystemPowerAction",
    "WdfInterruptSetExtendedPolicy",
    "WdfIoQueueAssignForwardProgressPolicy",
    "WdfPdoInitAssignContainerID",
    "WdfPdoInitAllowForwardingRequestToParent",
    "WdfRequestMarkCancelableEx",
    "WdfRequestIsReserved",
    "WdfRequestForwardToParentDeviceIoQueue",
    "WdfCxDeviceInitAllocate",
    "WdfCxDeviceInitAssignWdmIrpPreprocessCallback",
    "WdfCxDeviceInitSetIoInCallerContextCallback",
    "WdfCxDeviceInitSetRequestAttributes",
    "WdfCxDeviceInitSetFileObjectConfig",
    "WdfDeviceWdmDispatchIrp",
    "WdfDeviceWdmDispatchIrpToIoQueue",
    "WdfDeviceInitSetRemoveLockOptions",
    "WdfDeviceConfigureWdmIrpDispatchCallback",
    "WdfDmaEnablerConfigureSystemProfile",
    "WdfDmaTransactionInitializeUsingOffset",
    "WdfDmaTransactionGetTransferInfo",
    "WdfDmaTransactionSetChannelConfigurationCallback",
    "WdfDmaTransactionSetTransferCompleteCallback",
    "WdfDmaTransactionSetImmediateExecution",
    "WdfDmaTransactionAllocateResources",
    "WdfDmaTransactionSetDeviceAddressOffset",
    "WdfDmaTransactionFreeResources",
    "WdfDmaTransactionCancel",
    "WdfDmaTransactionWdmGetTransferContext",
    "WdfInterruptQueueWorkItemForIsr",
    "WdfInterruptTryToAcquireLock",
    "WdfIoQueueStopAndPurge",
    "WdfIoQueueStopAndPurgeSynchronously",
    "WdfIoTargetPurge",
    "WdfUsbTargetDeviceCreateWithParameters",
    "WdfUsbTargetDeviceQueryUsbCapability",
    "WdfUsbTargetDeviceCreateUrb",
    "WdfUsbTargetDeviceCreateIsochUrb",
    "WdfDeviceWdmAssignPowerFrameworkSettings",
    "WdfDmaTransactionStopSystemTransfer",
    "WdfCxVerifierKeBugCheck",
    "WdfInterruptReportActive",
    "WdfInterruptReportInactive",
    "WdfDeviceInitSetReleaseHardwareOrderOnFailure",
    "WdfGetTriageInfo",
    "WdfDeviceInitSetIoTypeEx",
    "WdfDeviceQueryPropertyEx",
    "WdfDeviceAllocAndQueryPropertyEx",
    "WdfDeviceAssignProperty",
    "WdfFdoInitQueryPropertyEx",
    "WdfFdoInitAllocAndQueryPropertyEx",
    "WdfDeviceStopIdleActual",
    "WdfDeviceResumeIdleActual",
    "WdfDeviceGetSelfIoTarget",
    "WdfDeviceInitAllowSelfIoTarget",
    "WdfIoTargetSelfAssignDefaultIoQueue",
    "WdfDeviceOpenDevicemapKey",
    "WdfDmaTransactionSetSingleTransferRequirement",
    "WdfCxDeviceInitSetPnpPowerEventCallbacks",
    "WdfFileObjectGetInitiatorProcessId",
    "WdfRequestGetRequestorProcessId",
    "WdfDeviceRetrieveCompanionTarget",
    "WdfCompanionTargetSendTaskSynchronously",
    "WdfCompanionTargetWdmGetCompanionProcess",
    "WdfDriverOpenPersistentStateRegistryKey",
    "WdfDriverErrorReportApiMissing",
    "WdfPdoInitRemovePowerDependencyOnParent",
    "WdfCxDeviceInitAllocateContext",
    "WdfCxDeviceInitGetTypedContextWorker",
    "WdfCxDeviceInitSetPowerPolicyEventCallbacks",
    "WdfDeviceSetDeviceInterfaceStateEx",
];

pub fn function_from_offset(offset: u64, ptr_size: u32) -> Option<WdfFunction> {
    if ptr_size == 0 || !offset.is_multiple_of(ptr_size as u64) {
        return None;
    }
    let index = u32::try_from(offset / ptr_size as u64).ok()?;
    let name = WDF_FUNCTIONS.get(usize::try_from(index).ok()?)?;
    Some(WdfFunction { name, index })
}

pub fn function_by_name(name: &str) -> Option<WdfFunction> {
    let want = normalize_name(name);
    let index = WDF_FUNCTIONS
        .iter()
        .position(|func| normalize_name(func) == want)?;
    Some(WdfFunction {
        name: WDF_FUNCTIONS[index],
        index: index as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_functions_use_wdffuncenum_slots() {
        // Slots checked against Wdf01000.sys WdfVersion; the earlier table had
        // every WdfRequest* entry 36 slots low, on the WdfPdo*/WdfRegistry* block.
        for (name, index) in [
            ("WdfIoQueueCreate", 152),
            ("WdfIoTargetCreate", 167),
            ("WdfObjectGetTypedContextWorker", 202),
            ("WdfRegistryQueryULong", 240),
            ("WdfRequestCreate", 247),
            ("WdfRequestComplete", 263),
            ("WdfRequestCompleteWithInformation", 265),
            ("WdfRequestRetrieveInputBuffer", 269),
            ("WdfRequestRetrieveOutputBuffer", 270),
        ] {
            assert_eq!(function_by_name(name).unwrap().index, index, "{name}");
            assert_eq!(
                function_from_offset(index as u64 * 8, 8).unwrap().name,
                name
            );
        }
        assert!(function_from_offset(WDF_FUNCTIONS.len() as u64 * 8, 8).is_none());

        // gdrv3.sys binds KMDF 1.9 with 396 in-image slots; 1.15+ binds a pointer.
        let old = BoundTable {
            table: 0x1_4000_7130,
            count: 396,
            minor: 9,
        };
        assert_eq!(old.slot(0x1_4000_74D0).unwrap().name, "WdfDriverCreate");
        assert_eq!(
            old.slot(0x1_4000_71F8).unwrap().name,
            "WdfControlDeviceInitAllocate"
        );
        assert!(old.slot(0x1_4000_7130 + 396 * 8).is_none());
        assert!(BoundTable { minor: 15, ..old }
            .slot(0x1_4000_74D0)
            .is_none());
        assert!(function_from_offset(0x86C, 8).is_none());
    }
}

/// A KMDF client's function table from its `WDF_BIND_INFO` (x64). Clients built
/// against KMDF 1.13 and earlier bind an in-image array of `count` slots at
/// `table` and read slots in place; later clients bind a pointer variable
/// there and index through it.
#[derive(Debug, Clone, Copy)]
pub struct BoundTable {
    pub table: u64,
    pub count: u64,
    pub minor: u32,
}

impl BoundTable {
    pub fn in_image(&self) -> bool {
        self.minor < 15
    }

    /// The function whose in-image slot is at `va`.
    pub fn slot(&self, va: u64) -> Option<WdfFunction> {
        let offset = va.checked_sub(self.table)?;
        if !self.in_image() || offset >= self.count * 8 {
            return None;
        }
        function_from_offset(offset, 8)
    }
}

/// Finds `WDF_BIND_INFO` by its `Component` pointer to the UTF-16
/// "KmdfLibrary" name, checking `Size` and major version 1.
pub fn bound_table(pe: &crate::formats::pe::PeFile, raw: &[u8]) -> Option<BoundTable> {
    if pe.arch != 64 {
        return None;
    }
    let name: Vec<u8> = "KmdfLibrary\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let data: Vec<(u32, &[u8])> = pe
        .sections
        .iter()
        .filter(|section| !section.is_executable() && section.raw_size != 0)
        .filter_map(|section| {
            let bytes = pe.rva_bytes(raw, section.virtual_address)?;
            Some((
                section.virtual_address,
                &bytes[..bytes.len().min(section.raw_size as usize)],
            ))
        })
        .collect();
    let component = data.iter().find_map(|(rva, bytes)| {
        let at = bytes
            .windows(name.len())
            .position(|window| window == name)?;
        Some(pe.image_base + u64::from(*rva) + at as u64)
    })?;
    data.iter().find_map(|(_, bytes)| {
        (8..bytes.len().saturating_sub(40))
            .step_by(8)
            .find_map(|at| {
                let field =
                    |offset: usize, len: usize| &bytes[at - 8 + offset..at - 8 + offset + len];
                let u32_at = |offset| u32::from_le_bytes(field(offset, 4).try_into().unwrap());
                let u64_at = |offset| u64::from_le_bytes(field(offset, 8).try_into().unwrap());
                (u64_at(8) == component && (0x28..=0x40).contains(&u32_at(0)) && u32_at(16) == 1)
                    .then(|| BoundTable {
                        table: u64_at(32),
                        count: u64::from(u32_at(28)),
                        minor: u32_at(20),
                    })
            })
    })
}

/// `bound_table` for the image last asked about on this thread; slot
/// resolution runs per instruction.
pub fn bound_table_cached(pe: &crate::formats::pe::PeFile, raw: &[u8]) -> Option<BoundTable> {
    type Key = (usize, usize, u64, u32, u32);
    thread_local! {
        static LAST: std::cell::Cell<Option<(Key, Option<BoundTable>)>> =
            const { std::cell::Cell::new(None) };
    }
    // A freed buffer can be reused for another image, so identity is included.
    let key = (
        raw.as_ptr() as usize,
        raw.len(),
        pe.image_base,
        pe.timestamp,
        pe.entry_point,
    );
    LAST.with(|last| match last.get() {
        Some((cached, table)) if cached == key => table,
        _ => {
            let table = bound_table(pe, raw);
            last.set(Some((key, table)));
            table
        }
    })
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
