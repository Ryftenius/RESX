mod api;
mod cache;
mod llvm_types;
mod symbols;

pub use api::{load_pdb_symbol, load_pdb_symbols, load_pdb_types};
use cache::*;
use llvm_types::*;
use symbols::*;

use crate::formats::pe::{parse_pe, read_u32};
use std::collections::{HashMap, HashSet};
use std::ffi::{c_void, CString};
use std::path::{Path, PathBuf};
use std::slice;
use std::sync::{Mutex, OnceLock};

const DEFAULT_MS_SYMBOL_SERVER: &str = "http://msdl.microsoft.com/download/symbols";
const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;
const S_OK: i32 = 0;

type FnSymInitialize = unsafe extern "system" fn(*mut c_void, *const u8, i32) -> i32;
type FnSymCleanup = unsafe extern "system" fn(*mut c_void) -> i32;
type FnSymSetOptions = unsafe extern "system" fn(u32) -> u32;
type FnSymLoadModuleEx = unsafe extern "system" fn(
    *mut c_void,
    *mut c_void,
    *const u8,
    *const u8,
    u64,
    u32,
    *mut c_void,
    u32,
) -> u64;
type FnSymFromName = unsafe extern "system" fn(*mut c_void, *const u8, *mut SymbolInfo) -> i32;
type FnSymEnumSymbols =
    unsafe extern "system" fn(*mut c_void, u64, *const u8, SymEnumSymbolsProc, usize) -> i32;
type FnSymEnumTypes = unsafe extern "system" fn(*mut c_void, u64, SymEnumSymbolsProc, usize) -> i32;
type FnSymGetTypeInfo = unsafe extern "system" fn(*mut c_void, u64, u32, u32, *mut c_void) -> i32;
type FnSymGetModuleInfo = unsafe extern "system" fn(*mut c_void, u64, *mut ImagehlpModule64) -> i32;
type FnSymSetSearchPath = unsafe extern "system" fn(*mut c_void, *const u8) -> i32;
type SymEnumSymbolsProc = unsafe extern "system" fn(*mut SymbolInfo, u32, usize) -> i32;

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryExW(name: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
    fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *const c_void;
    fn GetCurrentProcess() -> *mut c_void;
    fn LocalFree(ptr: *mut c_void) -> *mut c_void;
}

fn system_dbghelp() -> *mut c_void {
    // Keep the module alive for the lifetime of all cached function pointers.
    static MODULE: OnceLock<usize> = OnceLock::new();
    *MODULE.get_or_init(|| {
        let mut path = [0u16; 32768];
        // SAFETY: Windows writes at most the declared capacity.
        let len = unsafe { GetSystemDirectoryW(path.as_mut_ptr(), path.len() as u32) } as usize;
        let suffix: Vec<_> = "\\dbghelp.dll\0".encode_utf16().collect();
        if len == 0 || len + suffix.len() > path.len() {
            return 0;
        }
        path[len..len + suffix.len()].copy_from_slice(&suffix);
        // SAFETY: absolute, NUL-terminated system path. Dependencies also use
        // LOAD_LIBRARY_SEARCH_SYSTEM32, never the sample directory or CWD.
        unsafe { LoadLibraryExW(path.as_ptr(), std::ptr::null_mut(), 0x800) as usize }
    }) as *mut c_void
}

#[link(name = "urlmon")]
extern "system" {
    fn URLDownloadToFileW(
        p_caller: *mut c_void,
        sz_url: *const u16,
        sz_file_name: *const u16,
        dw_reserved: u32,
        lpfn_cb: *mut c_void,
    ) -> i32;
}

fn get_proc(module: *mut c_void, name: &[u8]) -> *const c_void {
    if module.is_null() || name.last() != Some(&0) {
        return std::ptr::null();
    }
    // SAFETY: `module` is live and `name` is a NUL-terminated byte string.
    unsafe { GetProcAddress(module, name.as_ptr()) }
}

#[repr(C)]
pub struct SymbolInfo {
    pub size_of_struct: u32,
    pub type_index: u32,
    pub reserved: [u64; 2],
    pub index: u32,
    pub size: u32,
    pub mod_base: u64,
    pub flags: u32,
    _pad: u32,
    pub value: u64,
    pub address: u64,
    pub register: u32,
    pub scope: u32,
    pub tag: u32,
    pub name_len: u32,
    pub max_name_len: u32,
    pub name: [u8; 512],
}

impl Default for SymbolInfo {
    fn default() -> Self {
        // SAFETY: SymbolInfo is a plain C-compatible record and all-zero is a valid initial state.
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[repr(C)]
struct ImagehlpModule64 {
    size_of_struct: u32,
    base_of_image: u64,
    image_size: u32,
    time_date_stamp: u32,
    check_sum: u32,
    num_syms: u32,
    sym_type: u32,
    module_name: [u8; 32],
    image_name: [u8; 256],
    loaded_image_name: [u8; 256],
    loaded_pdb_name: [u8; 256],
    cv_sig: u32,
    cv_data: [u8; 256 * 3],
    pdb_sig: u32,
    pdb_sig70: Guid,
    pdb_age: u32,
    pdb_unmatched: i32,
    dbg_unmatched: i32,
    line_numbers: i32,
    global_symbols: i32,
    type_info: i32,
    source_indexed: i32,
    publics: i32,
    machine_type: u32,
    reserved: u32,
}

impl Default for ImagehlpModule64 {
    fn default() -> Self {
        // SAFETY: ImagehlpModule64 is a plain C-compatible record and DbgHelp requires zero initialization.
        unsafe { std::mem::zeroed() }
    }
}

#[derive(Debug, Clone)]
pub struct PdbSymbol {
    pub name: String,
    pub rva: u32,
    pub va: u64,
    pub kind: String,
    pub type_id: u32,
    pub type_name: String,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct PdbTypeMember {
    pub name: String,
    pub offset: u64,
    pub type_id: u32,
    pub type_name: String,
    pub kind: String,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct PdbTypeInfo {
    pub type_id: u32,
    pub name: String,
    pub kind: String,
    pub size: u64,
    pub members: Vec<PdbTypeMember>,
}

struct EnumContext {
    h_proc: *mut c_void,
    module_base: u64,
    sym_get_type_info: FnSymGetTypeInfo,
    out: *mut Vec<PdbSymbol>,
}

struct TypeEnumContext {
    out: *mut Vec<TypeSeed>,
}

#[derive(Debug, Clone)]
struct TypeSeed {
    type_id: u32,
    name: String,
    tag: u32,
}

const TI_GET_SYMNAME: u32 = 1;
const TI_GET_LENGTH: u32 = 2;
const TI_GET_TYPE: u32 = 3;
const TI_GET_CALLING_CONVENTION: u32 = 26;
const TI_GET_BASETYPE: u32 = 5;
const TI_FINDCHILDREN: u32 = 7;
const TI_GET_OFFSET: u32 = 10;
const TI_GET_CHILDRENCOUNT: u32 = 13;
const TI_GET_SYMTAG: u32 = 0;
const TI_GET_IS_REFERENCE: u32 = 31;
const SYM_TAG_FUNCTION: u32 = 5;
const SYM_TAG_DATA: u32 = 7;
const SYM_TAG_PUBLIC: u32 = 10;
const SYM_TAG_UDT: u32 = 11;
const SYM_TAG_ENUM: u32 = 12;
const SYM_TAG_FUNCTION_TYPE: u32 = 13;
const SYM_TAG_POINTER_TYPE: u32 = 14;
const SYM_TAG_ARRAY_TYPE: u32 = 15;
const SYM_TAG_BASE_TYPE: u32 = 16;
const SYM_TAG_TYPEDEF: u32 = 17;
const SYM_TAG_BASE_CLASS: u32 = 18;

#[repr(C)]
struct TiFindChildrenHeader {
    count: u32,
    start: u32,
}

#[cfg(test)]
mod loader_tests {
    use super::*;

    #[test]
    fn dbghelp_is_loaded_from_the_windows_system_directory() {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetModuleFileNameW(module: *mut c_void, buffer: *mut u16, size: u32) -> u32;
        }
        let module = system_dbghelp();
        assert!(!module.is_null());
        let mut actual = [0u16; 32768];
        let mut system = [0u16; 32768];
        // SAFETY: both output buffers have their declared capacities and the module is live.
        let (a, s) = unsafe {
            (
                GetModuleFileNameW(module, actual.as_mut_ptr(), actual.len() as u32),
                GetSystemDirectoryW(system.as_mut_ptr(), system.len() as u32),
            )
        };
        assert!(a > 0 && a < actual.len() as u32 && s > 0 && s < system.len() as u32);
        assert_eq!(
            String::from_utf16_lossy(&actual[..a as usize]).to_lowercase(),
            format!(
                "{}\\dbghelp.dll",
                String::from_utf16_lossy(&system[..s as usize])
            )
            .to_lowercase()
        );
        assert_eq!(module, system_dbghelp());
    }
}
