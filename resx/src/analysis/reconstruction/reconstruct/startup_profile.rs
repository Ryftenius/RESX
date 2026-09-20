use super::FlowFunction;

const COOKIE_SOURCES: [&str; 4] = [
    "GetSystemTimeAsFileTime",
    "GetCurrentThreadId",
    "GetCurrentProcessId",
    "QueryPerformanceCounter",
];

pub(super) fn classify(node: &mut FlowFunction) {
    let matched = COOKIE_SOURCES
        .iter()
        .filter(|api| {
            node.edges
                .iter()
                .any(|edge| import_tail(&edge.target).eq_ignore_ascii_case(api))
        })
        .count();
    // The cookie initializer is a small leaf-like startup routine. Requiring the
    // complete API quorum and a bounded edge surface avoids labeling general
    // telemetry code that happens to consume the same process entropy sources.
    if matched < COOKIE_SOURCES.len() || node.edges.len() > 8 {
        return;
    }

    let mut deviations = Vec::new();
    if node.returns.is_empty() {
        deviations.push("no return instruction recovered".to_owned());
    }
    let foreign = node
        .edges
        .iter()
        .filter(|edge| {
            edge.target_source == "import"
                && !COOKIE_SOURCES
                    .iter()
                    .any(|api| import_tail(&edge.target).eq_ignore_ascii_case(api))
        })
        .map(|edge| edge.target.clone())
        .collect::<Vec<_>>();
    if !foreign.is_empty() {
        deviations.push(format!("additional imported calls: {}", foreign.join(", ")));
    }
    let unresolved_indirect = node
        .edges
        .iter()
        .filter(|edge| {
            edge.tags.iter().any(|tag| tag == "indirect") && edge.target_source == "unknown"
        })
        .count();
    if unresolved_indirect != 0 {
        deviations.push(format!(
            "{} unresolved indirect transfer(s)",
            unresolved_indirect
        ));
    }
    let extra_internal = node
        .edges
        .iter()
        .filter(|edge| {
            edge.target_source == "unknown" && !edge.tags.iter().any(|tag| tag == "indirect")
        })
        .count();
    if extra_internal != 0 {
        deviations.push(format!(
            "{} additional internal control transfer(s)",
            extra_internal
        ));
    }

    node.symbol_category = "internal-crt".to_owned();
    let profile = if deviations.is_empty() {
        "recognized MSVC security-cookie initialization profile (4/4 entropy-source APIs)"
            .to_owned()
    } else {
        format!(
            "MSVC security-cookie initialization profile with structural deviations: {}",
            deviations.join("; ")
        )
    };
    node.note = if node.note.is_empty() {
        profile
    } else {
        format!("{}; {}", node.note, profile)
    };
}

fn import_tail(name: &str) -> &str {
    name.rsplit('!').next().unwrap_or(name)
}

#[cfg(test)]
mod tests {
    use super::classify;
    use crate::analysis::reconstruction::reconstruct::{FlowEdge, FlowFunction};

    fn edge(name: &str) -> FlowEdge {
        FlowEdge {
            site_rva: String::new(),
            kind: "call".into(),
            target: format!("KERNEL32.dll!{name}"),
            target_rva: String::new(),
            target_va: String::new(),
            target_source: "import".into(),
            target_category: "microsoft-api".into(),
            thread_lane: 0,
            tags: vec!["import".into(), "indirect".into()],
            detail: String::new(),
            relation: "callee".into(),
            child: None,
        }
    }
    fn function(names: &[&str]) -> FlowFunction {
        FlowFunction {
            name: "sub_1000".into(),
            kind: "Function".into(),
            rva: "0x1000".into(),
            va: String::new(),
            section: ".text".into(),
            symbol_source: "synthetic".into(),
            symbol_category: "synthetic".into(),
            symbol_size: String::new(),
            prototype: String::new(),
            decode_bound: String::new(),
            thread_lane: 0,
            note: String::new(),
            status: "expanded".into(),
            edges: names.iter().map(|name| edge(name)).collect(),
            returns: vec!["0x1040".into()],
        }
    }

    #[test]
    fn recognizes_full_cookie_entropy_source_quorum() {
        let mut node = function(&super::COOKIE_SOURCES);
        classify(&mut node);
        assert_eq!(node.symbol_category, "internal-crt");
        assert!(node.note.contains("4/4"));
        assert!(!node.note.contains("deviations"));
    }

    #[test]
    fn partial_quorum_does_not_label_ordinary_code_as_crt() {
        let mut node = function(&super::COOKIE_SOURCES[..2]);
        classify(&mut node);
        assert_eq!(node.symbol_category, "synthetic");
    }

    #[test]
    fn broad_telemetry_function_is_not_a_cookie_initializer() {
        let mut node = function(&super::COOKIE_SOURCES);
        for name in [
            "GetTickCount64",
            "GetCommandLineW",
            "GetEnvironmentVariableW",
            "CreateFileW",
            "CloseHandle",
        ] {
            node.edges.push(edge(name));
        }
        classify(&mut node);
        assert_eq!(node.symbol_category, "synthetic");
    }

    #[test]
    fn reports_foreign_calls_as_profile_deviations() {
        let mut node = function(&super::COOKIE_SOURCES);
        node.edges.push(edge("CreateFileW"));
        classify(&mut node);
        assert!(node.note.contains("structural deviations"));
        assert!(node.note.contains("CreateFileW"));
    }
}
