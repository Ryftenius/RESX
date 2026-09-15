//! Optional comparison against separately recorded Microsoft dumpbin output.
//! Reads known valid images only; never launches an image or an external parser.
use resx_ffi::formats::pe::{parse_pe, read_runtime_functions};
#[test]
#[ignore = "requires RESX_UNWIND_ORACLE from recorded dumpbin /unwindinfo output"]
fn matches_independent_os_unwind_records() {
    let path = std::env::var_os("RESX_UNWIND_ORACLE").expect("RESX_UNWIND_ORACLE");
    let bytes = std::fs::read(path).unwrap();
    assert!(bytes.len() <= 16 * 1024 * 1024);
    let images: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    for image in images.as_array().unwrap() {
        let raw = std::fs::read(image["image"].as_str().unwrap()).unwrap();
        let pe = parse_pe(&raw).unwrap();
        let recovered = read_runtime_functions(&pe, &raw);
        let records = image["records"].as_array().unwrap();
        assert_eq!(recovered.len(), records.len(), "{}", image["image"]);
        for (actual, expected) in recovered.iter().zip(records) {
            let n = |field: &str| expected[field].as_u64().unwrap();
            assert_eq!(
                (
                    actual.begin_rva as u64,
                    actual.end_rva as u64,
                    actual.unwind_info_rva as u64
                ),
                (n("begin"), n("end"), n("info"))
            );
            assert_eq!(
                (
                    actual.unwind_version as u64,
                    actual.prolog_size as u64,
                    actual.unwind_code_count as u64
                ),
                (n("version"), n("prolog"), n("code_count")),
                "begin={:x}",
                actual.begin_rva
            );
            let scopes: Vec<_> = actual
                .epilog_scopes
                .iter()
                .map(|s| serde_json::json!([s.start_offset, s.end_offset]))
                .collect();
            assert_eq!(
                serde_json::json!(scopes),
                expected["epilogs"],
                "begin={:x}",
                actual.begin_rva
            );
            if !expected["stack"].is_null() {
                assert_eq!(
                    actual.stack_alloc_size as u64,
                    n("stack"),
                    "begin={:x}",
                    actual.begin_rva
                );
            }
        }
        println!("{}: {} records compared", image["image"], records.len());
    }
}
