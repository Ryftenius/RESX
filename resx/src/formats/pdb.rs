#[cfg(windows)]
#[path = "pdb/windows/mod.rs"]
mod win;

#[cfg(windows)]
pub use win::{load_pdb_symbol, load_pdb_symbols, load_pdb_types, PdbSymbol, PdbTypeInfo};

#[cfg(not(windows))]
pub fn load_pdb_symbol(
    _dll_path: &str,
    _func_name: &str,
    _sym_path: &str,
    _sym_server: &str,
    _pdb_path: &str,
    _image_base: u64,
    _verbose: bool,
    _reload: bool,
) -> Option<u32> {
    None
}

#[cfg(not(windows))]
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

#[cfg(not(windows))]
#[derive(Debug, Clone)]
pub struct PdbTypeMember {
    pub name: String,
    pub offset: u64,
    pub type_id: u32,
    pub type_name: String,
    pub kind: String,
    pub size: u64,
}

#[cfg(not(windows))]
#[derive(Debug, Clone)]
pub struct PdbTypeInfo {
    pub type_id: u32,
    pub name: String,
    pub kind: String,
    pub size: u64,
    pub members: Vec<PdbTypeMember>,
}

#[cfg(not(windows))]
pub fn load_pdb_symbols(
    _dll_path: &str,
    _sym_path: &str,
    _sym_server: &str,
    _pdb_path: &str,
    _verbose: bool,
    _reload: bool,
) -> Result<Vec<PdbSymbol>, String> {
    Err("PDB symbol enumeration is only supported on Windows".to_owned())
}

#[cfg(not(windows))]
pub fn load_pdb_types(
    _dll_path: &str,
    _sym_path: &str,
    _sym_server: &str,
    _pdb_path: &str,
    _verbose: bool,
    _reload: bool,
) -> Result<Vec<PdbTypeInfo>, String> {
    Err("PDB type enumeration is only supported on Windows".to_owned())
}
