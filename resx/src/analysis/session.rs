//! Demand-driven analysis over one immutable image.
//!
//! Image facts never depend on analyses. This coordinator owns reusable analysis
//! results and drops them with the image session, without global cache keys.

use std::sync::OnceLock;

use crate::formats::pe::PeFile;

use super::{
    image::ImageFacts,
    resolution::{ExportProvider, ResolutionReport},
};

pub struct AnalysisSession<'a> {
    image: ImageFacts<'a>,
    exports: &'a dyn ExportProvider,
    resolution: OnceLock<ResolutionReport>,
}

impl<'a> AnalysisSession<'a> {
    /// `pe` must describe `raw`, as returned by `formats::pe::parse_pe(raw)`.
    /// Uses no external export names. Use `with_exports` for name/hash recovery
    /// against a caller-selected dictionary or lazy provider.
    pub fn new(pe: &'a PeFile, raw: &'a [u8]) -> Self {
        Self::with_exports(pe, raw, super::resolution::dictionary::empty())
    }

    /// Bind an export snapshot to the session. Results never outlive these inputs.
    pub fn with_exports(pe: &'a PeFile, raw: &'a [u8], exports: &'a dyn ExportProvider) -> Self {
        Self {
            exports,
            image: ImageFacts::new(pe, raw),
            resolution: OnceLock::new(),
        }
    }

    pub fn image(&self) -> &ImageFacts<'a> {
        &self.image
    }

    pub fn exports(&self) -> &'a dyn ExportProvider {
        self.exports
    }

    #[cfg(test)]
    pub(crate) fn resolution_initialized(&self) -> bool {
        self.resolution.get().is_some()
    }

    pub fn resolution(&self) -> &ResolutionReport {
        self.resolution
            .get_or_init(|| super::resolution::analyze_in(&self.image, self.exports))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::image::tests::image;

    #[test]
    fn resolution_without_external_names_does_not_request_a_provider() {
        struct Unused;
        impl ExportProvider for Unused {
            fn dictionary(&self) -> &super::super::resolution::ExportDictionary {
                panic!("unexpected environment lookup");
            }
        }
        let pe = image();
        let mut raw = vec![0; 0x400];
        raw[0x200] = 0xc3;
        let session = AnalysisSession::with_exports(&pe, &raw, &Unused);
        assert!(session.resolution().resolved.is_empty());
    }

    #[test]
    fn encoded_names_and_module_inference_use_only_the_selected_dictionary() {
        use crate::analysis::image::tests::imported_image;
        use crate::analysis::resolution::ExportDictionary;

        let (pe, mut raw) = imported_image();
        raw[0x3a2..0x3b1].copy_from_slice(b"GetProcAddress\0");
        let code = [
            0x48, 0x83, 0xec, 0x28, // sub rsp, 28h
            0x31, 0xc9, // xor ecx, ecx (unknown module)
            0x48, 0x8d, 0x15, 0xb3, 0, 0, 0, // lea rdx, [name]
            0xff, 0x15, 0x4d, 1, 0, 0, // call [GetProcAddress]
            0x48, 0x83, 0xc4, 0x28, 0xc3,
        ];
        raw[0x200..0x200 + code.len()].copy_from_slice(&code);
        let mut alpha = ExportDictionary::default();
        alpha.add_exports("alpha.dll", ["CustomApi"]);
        let mut beta = ExportDictionary::default();
        beta.add_exports("beta.dll", ["CustomApi"]);

        for encoded in [false, true] {
            for (dest, byte) in raw[0x2c0..].iter_mut().zip(b"CustomApi\0") {
                *dest = byte ^ if encoded { 0x5a } else { 0 };
            }
            let first = AnalysisSession::with_exports(&pe, &raw, &alpha);
            let second = AnalysisSession::with_exports(&pe, &raw, &beta);
            let empty = AnalysisSession::new(&pe, &raw);
            for (session, owner) in [
                (&first, "alpha.dll"),
                (&second, "beta.dll"),
                (&first, "alpha.dll"),
            ] {
                let resolved = session
                    .resolution()
                    .resolved
                    .iter()
                    .find(|api| api.site == 0x100d)
                    .unwrap();
                assert_eq!(resolved.api.as_deref(), Some("CustomApi"));
                assert_eq!(resolved.module.as_deref(), Some(owner));
                assert_eq!(
                    resolved.api_source,
                    if encoded { "xor 0x5A" } else { "literal" }
                );
            }
            let unknown = empty
                .resolution()
                .resolved
                .iter()
                .find(|api| api.site == 0x100d)
                .unwrap();
            assert!(unknown.module.is_none());
            assert_eq!(
                unknown.api.as_deref(),
                if encoded { None } else { Some("CustomApi") }
            );
        }
    }

    #[test]
    fn metadata_does_not_trigger_resolution_and_threads_share_one_report() {
        let pe = image();
        let mut raw = vec![0; 0x400];
        raw[0x200] = 0xc3;
        let session = AnalysisSession::new(&pe, &raw);
        assert!(session.image().imports().is_empty());
        assert!(session.resolution.get().is_none());
        std::thread::scope(|scope| {
            let first = scope.spawn(|| session.resolution());
            let second = scope.spawn(|| session.resolution());
            assert!(std::ptr::eq(first.join().unwrap(), second.join().unwrap()));
        });
    }

    #[test]
    fn a_new_session_observes_changed_bytes_in_the_same_allocation() {
        let pe = image();
        let mut raw = vec![0; 0x400];
        raw[0x200..0x203].copy_from_slice(&[0xc3, 0x90, 0xc3]);
        {
            let session = AnalysisSession::new(&pe, &raw);
            assert!(session
                .resolution()
                .function_containing(&pe, &raw, 0x1001)
                .is_none());
        }
        raw[0x200] = 0x90;
        let session = AnalysisSession::new(&pe, &raw);
        assert!(session
            .resolution()
            .function_containing(&pe, &raw, 0x1001)
            .is_some());
    }
}
