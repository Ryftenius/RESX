//! Device declarations are tied to named API arguments, not nearby strings.
use super::{calls, dispatch, IoctlCodeCandidate, MajorFunctionAssignment};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize)]
pub struct DeviceEndpoint {
    pub id: String,
    pub device_name: Option<String>,
    pub aliases: Vec<String>,
    pub creation_api: String,
    pub creation_rva: String,
    pub driver_entry_object: bool,
    pub driver_argument: calls::Value,
    pub device_type: Option<u32>,
    pub characteristics: Option<u32>,
    pub secure_open: Option<bool>,
    pub exclusive: Option<bool>,
    pub default_sddl: Option<String>,
    pub security_source: String,
    pub association: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeviceLink {
    pub alias: Option<String>,
    pub target: Option<String>,
    pub site_rva: String,
    pub api: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct DeviceEvidence {
    pub endpoints: Vec<DeviceEndpoint>,
    pub symbolic_links: Vec<DeviceLink>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenProbe {
    pub access: u32,
    pub opened: Option<bool>,
    pub dacl_allowed: Option<bool>,
    pub win32_error: Option<u32>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LiveSecurity {
    pub requested_path: String,
    pub opened_path: String,
    pub object_name: Option<String>,
    pub dos_target: Option<String>,
    pub sddl: Option<String>,
    pub descriptor_source: String,
    pub token: String,
    pub token_elevated: Option<bool>,
    pub token_integrity_rid: Option<u32>,
    pub user_open_probes: Vec<OpenProbe>,
    pub matched_endpoint_ids: Vec<String>,
    pub limitations: Vec<String>,
    pub error: Option<String>,
}

fn text(call: &calls::CallEvidence, name: &str) -> Option<String> {
    call.details["strings"]
        .as_array()?
        .iter()
        .find(|s| s["argument"] == name)?["value"]
        .as_str()
        .map(str::to_owned)
}
fn value(call: &calls::CallEvidence, name: &str) -> calls::Value {
    call.arguments
        .iter()
        .find(|arg| arg.name == name)
        .map(|arg| arg.value.clone())
        .unwrap_or(calls::Value::Unknown)
}

pub(super) fn recover(
    calls: &[calls::CallEvidence],
    discovery: &dispatch::Recovery,
) -> DeviceEvidence {
    let symbolic_links: Vec<_> = calls
        .iter()
        .filter(|c| {
            c.category == "device-registration"
                && matches!(
                    c.api.as_str(),
                    "IoCreateSymbolicLink" | "IoCreateUnprotectedSymbolicLink"
                )
        })
        .take(128)
        .map(|c| DeviceLink {
            alias: text(c, "symbolic_link"),
            target: text(c, "target_name"),
            site_rva: format!("0x{:08X}", c.site_rva),
            api: c.api.clone(),
        })
        .collect();
    let endpoints = calls.iter().filter(|c| c.category=="device-registration" && matches!(c.api.as_str(), "IoCreateDevice" | "IoCreateDeviceSecure" | "WdmlibIoCreateDeviceSecure")).take(64).enumerate().map(|(index,c)| {
        let name=text(c,"device_name");
        let characteristics=value(c,"characteristics").constant().and_then(|n|u32::try_from(n).ok());
        let mut aliases:Vec<_>=symbolic_links.iter().filter(|link| name.as_ref().zip(link.target.as_ref()).is_some_and(|(a,b)| a.eq_ignore_ascii_case(b))).filter_map(|link|link.alias.clone()).collect();
        aliases.sort();aliases.dedup();
        DeviceEndpoint {
            id:format!("D{}",index+1),device_name:name,aliases,creation_api:c.api.clone(),creation_rva:format!("0x{:08X}",c.site_rva),
            driver_entry_object:discovery.device_creation_sites.contains(&c.site_rva),driver_argument:value(c,"driver_object"),
            device_type:value(c,"device_type").constant().and_then(|n|u32::try_from(n).ok()),characteristics,secure_open:characteristics.map(|n|n&0x100!=0),exclusive:value(c,"exclusive").constant().filter(|n|*n<=1).map(|n|n!=0),
            default_sddl:text(c,"default_sddl"),
            security_source:if c.api=="IoCreateDevice" {"No SDDL argument; INF/registry/framework/default policy not recovered"} else {"IoCreateDeviceSecure default argument; registry override and effective live security unobserved"}.into(),
            association:"Static creation and name-matched link arguments; API success, live DEVICE_OBJECT identity and per-device dispatch predicates unobserved".into(),
        }
    }).collect();
    DeviceEvidence { endpoints,symbolic_links, limitations:vec!["Device and SDDL values require named constructor arguments. Names alone do not prove an existing object or a reachable IOCTL. Dynamic/PnP/KMDF names and security may remain unknown.".into(),"Several devices can share a DRIVER_OBJECT dispatch routine. Candidate device IDs do not prove which device accepts a particular code. Internal device-control routes are not direct user DeviceIoControl routes.".into()] }
}

pub(super) fn associate(
    codes: &mut [IoctlCodeCandidate],
    endpoints: &DeviceEvidence,
    assignments: &[MajorFunctionAssignment],
) {
    for code in codes {
        code.request_channels = assignments
            .iter()
            .filter(|a| a.target_rva == code.owner_rva && matches!(a.major_index, 14 | 15))
            .map(|a| a.major_name.clone())
            .collect();
        code.request_channels.sort();
        code.request_channels.dedup();
        if !code.request_channels.is_empty()
            && code.evidence_status.starts_with("static-request-code-")
        {
            code.device_candidates = endpoints
                .endpoints
                .iter()
                .filter(|e| e.driver_entry_object)
                .map(|e| e.id.clone())
                .collect();
        }
        code.user_accessibility = if !code.request_channels.is_empty()
            && code
                .request_channels
                .iter()
                .all(|s| s == "IRP_MJ_INTERNAL_DEVICE_CONTROL")
        {
            "internal-dispatch; no direct user DeviceIoControl route"
        } else {
            "unverified; device routing, effective security and driver policy require live evidence"
        }
        .into();
    }
}

pub fn match_live(evidence: &DeviceEvidence, live: &mut LiveSecurity) {
    for endpoint in &evidence.endpoints {
        if endpoint.device_name.as_ref().is_some_and(|name| {
            live.object_name
                .as_ref()
                .or(live.dos_target.as_ref())
                .is_some_and(|actual| name.eq_ignore_ascii_case(actual))
        }) {
            live.matched_endpoint_ids.push(endpoint.id.clone());
        }
    }
    live.limitations.push("Name matching does not verify the loaded driver image, its DEVICE_OBJECT address, attached driver stack, or successful execution of any IOCTL.".into());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn live_name_matching_requires_the_complete_device_name() {
        let mut evidence = DeviceEvidence::default();
        evidence.endpoints.push(DeviceEndpoint {
            id: "D1".into(),
            device_name: Some("\\Device\\Example".into()),
            aliases: vec![],
            creation_api: String::new(),
            creation_rva: String::new(),
            driver_entry_object: true,
            driver_argument: calls::Value::Unknown,
            device_type: None,
            characteristics: None,
            secure_open: None,
            exclusive: None,
            default_sddl: None,
            security_source: String::new(),
            association: String::new(),
        });
        let mut live = LiveSecurity {
            object_name: Some("\\Device\\Example\\child".into()),
            ..Default::default()
        };
        match_live(&evidence, &mut live);
        assert!(live.matched_endpoint_ids.is_empty());
        live.object_name = Some("\\device\\example".into());
        match_live(&evidence, &mut live);
        assert_eq!(live.matched_endpoint_ids, ["D1"]);
    }
}

#[cfg(test)]
mod fixtures;
