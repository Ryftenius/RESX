//! Evidence contracts, including negative controls. Failures expose unsupported
//! classifications; they must not be converted into ignored or passing tests.
use super::*;
use crate::formats::pe::{parse_pe, PeSection, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ};

fn ordinary_dll() -> PeFile {
    // Minimal ordinary PE32+ headers. This is an explicit unit-test fixture,
    // not a runtime trace or evidence about a deployed binary.
    let mut raw = vec![0u8; 0x400];
    raw[..2].copy_from_slice(b"MZ");
    raw[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    raw[0x80..0x84].copy_from_slice(b"PE\0\0");
    raw[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    raw[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    raw[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
    raw[0x96..0x98].copy_from_slice(&0x2022u16.to_le_bytes());
    raw[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
    raw[0xdc..0xde].copy_from_slice(&3u16.to_le_bytes());
    raw[0x188..0x18d].copy_from_slice(b".text");
    parse_pe(&raw).expect("ordinary PE headers")
}

fn packer_candidates(strings: &[&str], sections: &[&str]) -> Vec<String> {
    let mut candidates = Vec::new();
    apply_packer_heuristics(
        &mut candidates,
        &ordinary_dll(),
        &sections.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        &[],
        &strings.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        &[],
    );
    candidates.into_iter().map(|(name, _)| name).collect()
}

#[test]
fn compression_vocabulary_is_not_an_mpress_marker() {
    for word in ["compression", "decompression", "compressbuffer"] {
        assert!(
            !packer_candidates(&[word], &[".text", ".rdata"]).contains(&"MPRESS".into()),
            "false MPRESS candidate from {word}"
        );
    }
}

#[test]
fn quoted_protector_names_do_not_establish_packing() {
    assert!(
        packer_candidates(
            &["documentation: upx! vmprotect themida are supported file formats"],
            &[".text", ".rdata"],
        )
        .is_empty(),
        "ordinary text must not establish a packer classification"
    );
}

#[test]
fn structural_packer_markers_remain_candidates() {
    assert!(packer_candidates(&[], &["mpress1", "mpress2"]).contains(&"MPRESS".into()));
    assert!(packer_candidates(&[], &["upx0", "upx1"]).contains(&"UPX".into()));
}

#[test]
fn ordinary_sections_without_markers_have_no_packer_candidate() {
    assert!(packer_candidates(&["ordinary application"], &[".text", ".rdata"]).is_empty());
}

#[test]
fn renaming_a_user_dll_does_not_make_it_a_kernel_driver() {
    let pe = ordinary_dll();
    assert_eq!(detect_image_kind(&pe, "fixture.dll"), "DLL");
    assert_eq!(detect_image_kind(&pe, "fixture.sys"), "DLL");
}

#[test]
fn section_permissions_follow_flags_not_names() {
    let mut section = PeSection {
        name: ".text".into(),
        virtual_address: 0x1000,
        virtual_size: 0x200,
        raw_offset: 0x400,
        raw_size: 0x200,
        characteristics: IMAGE_SCN_MEM_READ,
        entropy: 0.0,
    };
    assert!(!section.is_executable());
    assert_eq!(section.protection_string(), "R");
    section.name = ".data".into();
    section.characteristics |= IMAGE_SCN_MEM_EXECUTE;
    assert!(section.is_executable());
    assert_eq!(section.protection_string(), "RX");
}
