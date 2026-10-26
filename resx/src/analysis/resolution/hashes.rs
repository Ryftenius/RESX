//! Inversion of API and module name hashes. Hash functions are not identified from
//! code; instead a catalog of common constructions, widened with the rotate counts,
//! multipliers and seeds found in the resolver itself, is evaluated over known names
//! until one construction explains the constants the resolver is called with.

use std::collections::{BTreeSet, HashMap};

#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct Hints {
    /// Right-rotate counts (left rotates are stored as `32 - n`).
    pub rotates: BTreeSet<u32>,
    pub multipliers: BTreeSet<u32>,
    pub seeds: BTreeSet<u32>,
    pub crc: bool,
}

impl Hints {
    pub fn merge(&mut self, other: &Hints) {
        self.rotates.extend(&other.rotates);
        self.multipliers.extend(&other.multipliers);
        self.seeds.extend(&other.seeds);
        self.crc |= other.crc;
    }

    /// Whether the code does hash-like arithmetic at all.
    pub fn any(&self) -> bool {
        !self.rotates.is_empty() || !self.multipliers.is_empty() || self.crc
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Algo {
    RorAdd(u32),
    RorXor(u32),
    MulAdd {
        seed: u32,
        mul: u32,
    },
    /// FNV-1 order: multiply, then xor.
    MulXor {
        seed: u32,
        mul: u32,
    },
    /// FNV-1a order: xor, then multiply.
    XorMul {
        seed: u32,
        mul: u32,
    },
    Crc32,
    Joaat,
    Fnv1a64,
}

const FNV_SEED: u32 = 0x811C_9DC5;
const FNV_PRIME: u32 = 0x0100_0193;

impl Algo {
    fn label(self) -> String {
        match self {
            Algo::RorAdd(n) => format!("ror{n}-add"),
            Algo::RorXor(n) => format!("ror{n}-xor"),
            Algo::MulAdd {
                seed: 5381,
                mul: 33,
            } => "djb2".to_owned(),
            Algo::MulAdd {
                seed: 0,
                mul: 65599,
            } => "sdbm".to_owned(),
            Algo::MulXor {
                seed: FNV_SEED,
                mul: FNV_PRIME,
            } => "fnv-1".to_owned(),
            Algo::XorMul {
                seed: FNV_SEED,
                mul: FNV_PRIME,
            } => "fnv-1a".to_owned(),
            Algo::MulAdd { seed, mul } => format!("mul-add (seed 0x{seed:X}, x{mul})"),
            Algo::MulXor { seed, mul } => format!("mul-xor (seed 0x{seed:X}, x{mul})"),
            Algo::XorMul { seed, mul } => format!("xor-mul (seed 0x{seed:X}, x{mul})"),
            Algo::Crc32 => "crc32".to_owned(),
            Algo::Joaat => "jenkins one-at-a-time".to_owned(),
            Algo::Fnv1a64 => "fnv-1a/64".to_owned(),
        }
    }

    fn hash(self, bytes: &[u8]) -> u64 {
        match self {
            Algo::RorAdd(n) => u64::from(
                bytes
                    .iter()
                    .fold(0u32, |h, &b| h.rotate_right(n).wrapping_add(u32::from(b))),
            ),
            Algo::RorXor(n) => u64::from(
                bytes
                    .iter()
                    .fold(0u32, |h, &b| h.rotate_right(n) ^ u32::from(b)),
            ),
            Algo::MulAdd { seed, mul } => u64::from(
                bytes
                    .iter()
                    .fold(seed, |h, &b| h.wrapping_mul(mul).wrapping_add(u32::from(b))),
            ),
            Algo::MulXor { seed, mul } => u64::from(
                bytes
                    .iter()
                    .fold(seed, |h, &b| h.wrapping_mul(mul) ^ u32::from(b)),
            ),
            Algo::XorMul { seed, mul } => u64::from(
                bytes
                    .iter()
                    .fold(seed, |h, &b| (h ^ u32::from(b)).wrapping_mul(mul)),
            ),
            Algo::Crc32 => u64::from(crate::analysis::codec::crc32(bytes)),
            Algo::Joaat => {
                let mut h = bytes.iter().fold(0u32, |h, &b| {
                    let h = h.wrapping_add(u32::from(b));
                    let h = h.wrapping_add(h << 10);
                    h ^ (h >> 6)
                });
                h = h.wrapping_add(h << 3);
                h ^= h >> 11;
                u64::from(h.wrapping_add(h << 15))
            }
            Algo::Fnv1a64 => bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &b| {
                (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
            }),
        }
    }
}

/// How a name is turned into bytes before hashing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Form {
    case: Case,
    terminator: bool,
    wide: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Case {
    AsIs,
    Lower,
    Upper,
}

impl Form {
    fn all() -> impl Iterator<Item = Form> {
        [Case::AsIs, Case::Lower, Case::Upper]
            .into_iter()
            .flat_map(|case| {
                [(false, false), (true, false), (false, true), (true, true)]
                    .into_iter()
                    .map(move |(terminator, wide)| Form {
                        case,
                        terminator,
                        wide,
                    })
            })
    }

    fn bytes(self, name: &str, out: &mut Vec<u8>) {
        out.clear();
        for byte in name.bytes() {
            let byte = match self.case {
                Case::AsIs => byte,
                Case::Lower => byte.to_ascii_lowercase(),
                Case::Upper => byte.to_ascii_uppercase(),
            };
            out.push(byte);
            if self.wide {
                out.push(0);
            }
        }
        if self.terminator {
            out.push(0);
            if self.wide {
                out.push(0);
            }
        }
    }

    fn label(self) -> String {
        let mut parts = Vec::new();
        match self.case {
            Case::AsIs => {}
            Case::Lower => parts.push("lowercase"),
            Case::Upper => parts.push("uppercase"),
        }
        if self.wide {
            parts.push("UTF-16");
        }
        if self.terminator {
            parts.push("with NUL");
        }
        parts.join(", ")
    }
}

pub(super) struct Inversion {
    pub algorithm: String,
    pub names: HashMap<u64, String>,
}

/// The best construction so far: hits, whether it was suggested, and what it named.
struct Candidate {
    hits: usize,
    hinted: bool,
    algo: Algo,
    form: Form,
    names: HashMap<u64, String>,
}

/// Algorithms suggested by the resolver's own instructions, then the common ones.
fn catalog(hints: &Hints) -> (Vec<Algo>, Vec<Algo>) {
    let mut hinted = Vec::new();
    for &n in &hints.rotates {
        hinted.push(Algo::RorAdd(n));
        hinted.push(Algo::RorXor(n));
    }
    let mut seeds: BTreeSet<u32> = hints.seeds.clone();
    seeds.extend([0, 5381, FNV_SEED]);
    for &mul in &hints.multipliers {
        for &seed in &seeds {
            hinted.push(Algo::MulAdd { seed, mul });
            hinted.push(Algo::MulXor { seed, mul });
            hinted.push(Algo::XorMul { seed, mul });
        }
    }
    if hints.crc {
        hinted.push(Algo::Crc32);
    }
    let defaults = [
        Algo::RorAdd(13),
        Algo::RorXor(13),
        Algo::RorAdd(7),
        Algo::MulAdd {
            seed: 5381,
            mul: 33,
        },
        Algo::MulXor {
            seed: 5381,
            mul: 33,
        },
        Algo::MulAdd {
            seed: 0,
            mul: 65599,
        },
        Algo::XorMul {
            seed: FNV_SEED,
            mul: FNV_PRIME,
        },
        Algo::MulXor {
            seed: FNV_SEED,
            mul: FNV_PRIME,
        },
        Algo::Crc32,
        Algo::Joaat,
        Algo::Fnv1a64,
    ]
    .into_iter()
    .filter(|algo| !hinted.contains(algo))
    .collect();
    (hinted, defaults)
}

/// Names for as many of `values` as one hash construction explains. A construction
/// suggested by the resolver may stand on one match; an unsuggested one needs two,
/// unless it was given a single constant.
pub(super) fn invert(values: &[u64], hints: &Hints, names: &[&str]) -> Option<Inversion> {
    let wanted: BTreeSet<u64> = values.iter().copied().collect();
    if wanted.is_empty() || names.is_empty() {
        return None;
    }
    let (hinted, defaults) = catalog(hints);
    let mut best: Option<Candidate> = None;
    let mut buffer = Vec::with_capacity(64);
    'search: for (algos, hinted) in [(&hinted, true), (&defaults, false)] {
        for &algo in algos {
            for form in Form::all() {
                let mut found = HashMap::new();
                for name in names {
                    form.bytes(name, &mut buffer);
                    let value = algo.hash(&buffer);
                    if wanted.contains(&value) {
                        found.entry(value).or_insert_with(|| (*name).to_owned());
                    }
                }
                let hits = found.len();
                if hits > 0 && best.as_ref().is_none_or(|best| hits > best.hits) {
                    best = Some(Candidate {
                        hits,
                        hinted,
                        algo,
                        form,
                        names: found,
                    });
                    if hits == wanted.len() {
                        break 'search;
                    }
                }
            }
        }
        // A construction the resolver's own code suggests settles it; the common
        // catalog is only a fallback.
        if best.is_some() {
            break;
        }
    }
    let best = best?;
    if best.hits < 2 && !best.hinted && wanted.len() > 1 {
        return None;
    }
    let form = best.form.label();
    Some(Inversion {
        algorithm: if form.is_empty() {
            best.algo.label()
        } else {
            format!("{} ({form})", best.algo.label())
        },
        names: best.names,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ror13(name: &str) -> u64 {
        Algo::RorAdd(13).hash(name.as_bytes())
    }

    #[test]
    fn constructions_match_their_reference_values() {
        // Metasploit block_api: ror13 over the uppercase UTF-16 module name and the
        // ASCII function name, both with terminators, summed.
        let mut module = Vec::new();
        Form {
            case: Case::Upper,
            terminator: true,
            wide: true,
        }
        .bytes("kernel32.dll", &mut module);
        let combined = Algo::RorAdd(13).hash(&module) + Algo::RorAdd(13).hash(b"LoadLibraryA\0");
        assert_eq!(combined as u32, 0x0726_774C);
        assert_eq!(Algo::RorAdd(13).hash(b"ab"), 0x0308_0062);
        assert_eq!(
            Algo::XorMul {
                seed: FNV_SEED,
                mul: FNV_PRIME
            }
            .hash(b"a"),
            0xE40C_292C
        );
        assert_eq!(
            Algo::MulAdd {
                seed: 5381,
                mul: 33
            }
            .hash(b"a"),
            177_670
        );
    }

    #[test]
    fn hinted_rotation_inverts_a_single_constant() {
        let names = ["VirtualAlloc", "VirtualFree", "Sleep"];
        let hints = Hints {
            rotates: [13].into_iter().collect(),
            ..Hints::default()
        };
        let inversion = invert(&[ror13("VirtualAlloc")], &hints, &names).unwrap();
        assert_eq!(inversion.algorithm, "ror13-add");
        assert_eq!(
            inversion
                .names
                .get(&ror13("VirtualAlloc"))
                .map(String::as_str),
            Some("VirtualAlloc")
        );
    }

    #[test]
    fn unsuggested_constructions_need_corroboration() {
        let names = ["VirtualAlloc", "VirtualFree"];
        assert!(invert(
            &[ror13("VirtualAlloc"), 0x1234_5678],
            &Hints::default(),
            &names
        )
        .is_none());
        let both = invert(
            &[ror13("VirtualAlloc"), ror13("VirtualFree")],
            &Hints::default(),
            &names,
        )
        .unwrap();
        assert_eq!(both.names.len(), 2);
    }
}
