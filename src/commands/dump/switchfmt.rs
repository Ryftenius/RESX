pub(super) fn format_class_value(value: u32) -> String {
    format!("0x{:X}", value)
}

pub(super) fn format_target_symbol_spaced(name: &str) -> String {
    if let Some(pos) = name.find('+') {
        format!("{} {}", &name[..pos], &name[pos..])
    } else {
        name.to_owned()
    }
}

pub(super) fn format_case_summary(classes: &[u32]) -> String {
    let preview = summarize_case_values(classes, 4);
    format!("{} case(s): {}", classes.len(), preview)
}

pub(super) fn format_case_values(classes: &[u32]) -> String {
    let mut parts = Vec::new();
    let mut i = 0usize;
    while i < classes.len() {
        let start = classes[i];
        let mut end = start;
        while i + 1 < classes.len() && classes[i + 1] == end + 1 {
            i += 1;
            end = classes[i];
        }
        if start == end {
            parts.push(format_class_value(start));
        } else {
            parts.push(format!(
                "{}..{}",
                format_class_value(start),
                format_class_value(end)
            ));
        }
        i += 1;
    }
    parts.join(", ")
}

pub(super) fn summarize_case_values(classes: &[u32], limit: usize) -> String {
    let values = format_case_values(classes);
    let parts: Vec<&str> = values.split(", ").collect();
    if parts.len() <= limit {
        values
    } else {
        format!(
            "{}, +{} more",
            parts[..limit].join(", "),
            parts.len() - limit
        )
    }
}
