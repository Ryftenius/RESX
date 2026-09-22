use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SequenceChange {
    Equal,
    Changed,
    Added,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SequenceAlignmentRow {
    pub left: Option<usize>,
    pub right: Option<usize>,
    pub change: SequenceChange,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SequenceAlignment {
    pub rows: Vec<SequenceAlignmentRow>,
    pub equal: usize,
    pub changed: usize,
    pub added: usize,
    pub removed: usize,
    pub similarity: u8,
    pub exact: bool,
}

fn push_gap(
    rows: &mut Vec<SequenceAlignmentRow>,
    left: std::ops::Range<usize>,
    right: std::ops::Range<usize>,
) {
    let paired = left.len().min(right.len());
    for offset in 0..paired {
        rows.push(SequenceAlignmentRow {
            left: Some(left.start + offset),
            right: Some(right.start + offset),
            change: SequenceChange::Changed,
        });
    }
    for index in left.start + paired..left.end {
        rows.push(SequenceAlignmentRow {
            left: Some(index),
            right: None,
            change: SequenceChange::Removed,
        });
    }
    for index in right.start + paired..right.end {
        rows.push(SequenceAlignmentRow {
            left: None,
            right: Some(index),
            change: SequenceChange::Added,
        });
    }
}

fn dynamic_alignment(left: &[String], right: &[String]) -> Vec<SequenceAlignmentRow> {
    let columns = right.len() + 1;
    let mut lengths = vec![0u32; (left.len() + 1) * columns];
    for i in (0..left.len()).rev() {
        for j in (0..right.len()).rev() {
            lengths[i * columns + j] = if left[i] == right[j] {
                lengths[(i + 1) * columns + j + 1] + 1
            } else {
                lengths[(i + 1) * columns + j].max(lengths[i * columns + j + 1])
            };
        }
    }
    let mut anchors = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < left.len() && j < right.len() {
        if left[i] == right[j] {
            anchors.push((i, j));
            i += 1;
            j += 1;
        } else if lengths[(i + 1) * columns + j] >= lengths[i * columns + j + 1] {
            i += 1;
        } else {
            j += 1;
        }
    }
    let mut rows = Vec::with_capacity(left.len().max(right.len()));
    let (mut left_start, mut right_start) = (0usize, 0usize);
    for (left_index, right_index) in anchors {
        push_gap(&mut rows, left_start..left_index, right_start..right_index);
        rows.push(SequenceAlignmentRow {
            left: Some(left_index),
            right: Some(right_index),
            change: SequenceChange::Equal,
        });
        left_start = left_index + 1;
        right_start = right_index + 1;
    }
    push_gap(&mut rows, left_start..left.len(), right_start..right.len());
    rows
}

fn bounded_alignment(left: &[String], right: &[String]) -> Vec<SequenceAlignmentRow> {
    const LOOKAHEAD: usize = 64;
    let mut rows = Vec::with_capacity(left.len().max(right.len()));
    let (mut i, mut j) = (0usize, 0usize);
    while i < left.len() && j < right.len() {
        if left[i] == right[j] {
            rows.push(SequenceAlignmentRow {
                left: Some(i),
                right: Some(j),
                change: SequenceChange::Equal,
            });
            i += 1;
            j += 1;
            continue;
        }
        let right_match = right[j + 1..right.len().min(j + LOOKAHEAD + 1)]
            .iter()
            .position(|item| item == &left[i])
            .map(|offset| offset + 1);
        let left_match = left[i + 1..left.len().min(i + LOOKAHEAD + 1)]
            .iter()
            .position(|item| item == &right[j])
            .map(|offset| offset + 1);
        match (left_match, right_match) {
            (Some(left_distance), Some(right_distance)) if left_distance <= right_distance => {
                push_gap(&mut rows, i..i + left_distance, j..j);
                i += left_distance;
            }
            (_, Some(right_distance)) => {
                push_gap(&mut rows, i..i, j..j + right_distance);
                j += right_distance;
            }
            (Some(left_distance), None) => {
                push_gap(&mut rows, i..i + left_distance, j..j);
                i += left_distance;
            }
            (None, None) => {
                push_gap(&mut rows, i..i + 1, j..j + 1);
                i += 1;
                j += 1;
            }
        }
    }
    push_gap(&mut rows, i..left.len(), j..right.len());
    rows
}

/// Aligns two normalized instruction streams. Dynamic LCS is used while the caller's
/// memory budget permits it; larger inputs use bounded lookahead so hostile or unusually
/// large functions cannot force quadratic memory use.
pub fn align_instruction_sequences(
    left: &[String],
    right: &[String],
    max_cells: usize,
) -> SequenceAlignment {
    let cells = left
        .len()
        .saturating_add(1)
        .saturating_mul(right.len().saturating_add(1));
    let rows = if cells <= max_cells.max(1) {
        dynamic_alignment(left, right)
    } else {
        bounded_alignment(left, right)
    };
    let mut result = SequenceAlignment {
        rows,
        equal: 0,
        changed: 0,
        added: 0,
        removed: 0,
        similarity: 0,
        exact: left == right,
    };
    for row in &result.rows {
        match row.change {
            SequenceChange::Equal => result.equal += 1,
            SequenceChange::Changed => result.changed += 1,
            SequenceChange::Added => result.added += 1,
            SequenceChange::Removed => result.removed += 1,
        }
    }
    let denominator = left.len().max(right.len());
    result.similarity = result
        .equal
        .saturating_mul(100)
        .checked_div(denominator)
        .unwrap_or(100)
        .min(100) as u8;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn aligns_changed_and_inserted_instructions() {
        let report = align_instruction_sequences(
            &values(&["push reg:gpr64", "mov reg:gpr64", "ret"]),
            &values(&["push reg:gpr64", "xor reg:gpr32", "call import", "ret"]),
            1_000,
        );
        assert_eq!(report.equal, 2);
        assert_eq!(report.changed, 1);
        assert_eq!(report.added, 1);
        assert_eq!(report.removed, 0);
        assert!(!report.exact);
    }

    #[test]
    fn empty_streams_are_identical() {
        let report = align_instruction_sequences(&[], &[], 1);
        assert_eq!(report.similarity, 100);
        assert!(report.exact);
    }

    #[test]
    fn bounded_path_retains_anchors() {
        let report = align_instruction_sequences(
            &values(&["a", "b", "c"]),
            &values(&["a", "x", "b", "c"]),
            1,
        );
        assert_eq!(report.equal, 3);
        assert_eq!(report.added, 1);
    }
}
