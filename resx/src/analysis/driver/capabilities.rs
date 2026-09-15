use crate::formats::pe::ImportDll;
use serde::Serialize;
use std::collections::BTreeMap;

use super::HypervisorReport;

#[derive(Debug, Clone, Serialize)]
pub struct DriverCapability {
    pub capability: String,
    pub confidence: String,
    pub evidence: String,
    pub apis: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<DriverCapabilityReference>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriverCapabilityReference {
    pub rva: String,
    pub owner: String,
    pub instruction: String,
}

pub(super) fn analyze(imports: &[ImportDll]) -> Vec<DriverCapability> {
    let mut grouped: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    for dll in imports {
        for entry in &dll.entries {
            let lower = entry.name.to_ascii_lowercase();
            for capability in api_capabilities(&lower) {
                grouped
                    .entry(capability)
                    .or_default()
                    .push(format!("{}!{}", dll.dll, entry.name));
            }
        }
    }
    grouped
        .into_iter()
        .map(|(capability, mut apis)| {
            apis.sort();
            apis.dedup();
            DriverCapability {
                capability: capability.into(),
                confidence: "import-surface".into(),
                evidence:
                    "named imported API with established kernel semantics; invocation is unobserved"
                        .into(),
                apis,
                references: Vec::new(),
            }
        })
        .collect()
}

pub(super) fn add_hypervisor_capabilities(
    capabilities: &mut Vec<DriverCapability>,
    hypervisor: &HypervisorReport,
) {
    for indicator in hypervisor
        .instruction_evidence
        .iter()
        .chain(&hypervisor.register_evidence)
        .filter(|indicator| indicator.capability.contains("SLAT hook machinery"))
    {
        capabilities.push(DriverCapability {
            capability: format!("{} {}", indicator.vendor, indicator.capability),
            confidence: "static-correlation".into(),
            evidence: "correlated SLAT fault state, dynamic root selection, invalidation, and virtualization-entry evidence".into(),
            apis: Vec::new(),
            references: indicator
                .sites
                .iter()
                .map(|site| DriverCapabilityReference {
                    rva: site.rva.clone(),
                    owner: site.owner.clone(),
                    instruction: site.instruction.clone(),
                })
                .collect(),
        });
    }
    capabilities.sort_by(|left, right| left.capability.cmp(&right.capability));
}

fn api_capabilities(name: &str) -> Vec<&'static str> {
    let mut out = Vec::new();
    if matches!(
        name,
        "mmmapiospace"
            | "mmmapiospaceex"
            | "mmunmapiospace"
            | "mmgetphysicaladdress"
            | "mmcopymemory"
            | "mmmaplockedpagesspecifycache"
    ) {
        out.push("physical or device memory mapping");
    }
    if matches!(
        name,
        "mmprobeandlockpages"
            | "mmunlockpages"
            | "mmgetsystemaddressformdlsafe"
            | "ioallocatemdl"
            | "iofreemdl"
            | "mmbuildmdlfornonpagedpool"
    ) {
        out.push("MDL and locked-memory access");
    }
    if matches!(
        name,
        "pslookupprocessbyprocessid"
            | "pslookupthreadbythreadid"
            | "kestackattachprocess"
            | "keunstackdetachprocess"
            | "mmcopyvirtualmemory"
            | "zwreadvirtualmemory"
            | "zwwritevirtualmemory"
    ) {
        out.push("cross-process inspection or memory access");
    }
    if matches!(
        name,
        "iocalldriver"
            | "iobuilddeviceiocontrolrequest"
            | "iobuildasynchronousfsdrequest"
            | "iobuildsynchronousfsdrequest"
            | "zwdeviceiocontrolfile"
    ) {
        out.push("down-stack or device-control requests");
    }
    if matches!(
        name,
        "halgetbusdatabyoffset"
            | "halsetbusdatabyoffset"
            | "iogetdeviceproperty"
            | "iogetdevicepropertydata"
            | "ioreadpartitiontableex"
    ) {
        out.push("hardware, bus, or device enumeration");
    }
    if matches!(
        name,
        "iogetdmaadapter"
            | "halgetadapter"
            | "allocatecommonbuffer"
            | "allocatecommonbufferex"
            | "maptransfer"
            | "buildscattergatherlist"
    ) {
        out.push("DMA orchestration");
    }
    if name.starts_with("pssetcreateprocessnotifyroutine")
        || name.starts_with("pssetcreatethreadnotifyroutine")
        || name.starts_with("pssetloadimagenotifyroutine")
        || name.starts_with("obregistercallbacks")
        || name.starts_with("cmregistercallback")
    {
        out.push("process, image, object, or registry monitoring");
    }
    if name.starts_with("flt") {
        out.push("file-system minifilter operations");
    }
    if name.starts_with("ndis") || name.starts_with("fwps") || name.starts_with("fwpm") {
        out.push("network filtering or NDIS operations");
    }
    if name.starts_with("wsk") || name.starts_with("tdi") {
        out.push("kernel network communication");
    }
    if name.starts_with("zwopenkey")
        || name.starts_with("zwqueryvaluekey")
        || name.starts_with("zwsetvaluekey")
        || name.starts_with("rtlqueryregistry")
    {
        out.push("registry configuration access");
    }
    if matches!(
        name,
        "exallocatepool"
            | "exallocatepool2"
            | "exallocatepool3"
            | "exallocatepoolwithtag"
            | "exfreepool"
            | "exfreepoolwithtag"
    ) {
        out.push("kernel pool allocation");
    }
    if name.starts_with("hvl") || name.contains("hypercall") || name.starts_with("vid") {
        out.push("Windows hypervisor interface consumption");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::api_capabilities;

    #[test]
    fn exact_api_semantics_avoid_generic_name_guesses() {
        assert!(api_capabilities("mmmapiospace").contains(&"physical or device memory mapping"));
        assert!(api_capabilities("pslookupprocessbyprocessid")
            .contains(&"cross-process inspection or memory access"));
        assert!(api_capabilities("map").is_empty());
    }
}
