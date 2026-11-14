//! ELF hardening analysis built on `goblin`.
//!
//! All detection logic is based on loadable metadata (program headers,
//! dynamic section, dynamic/static symbol tables) so it works on stripped
//! firmware binaries and does not assume a glibc host.

use crate::dangerdb;
use crate::model::*;
use anyhow::{Context, Result};
use goblin::elf::dynamic::{DF_1_NOW, DF_BIND_NOW};
use goblin::elf::program_header::{PF_W, PF_X, PT_GNU_RELRO, PT_GNU_STACK, PT_LOAD};
use goblin::elf::section_header::SHN_UNDEF;
use goblin::elf::{header, Elf};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

const CANARY_SYMBOLS: &[&str] = &["__stack_chk_fail", "__stack_chk_fail_local"];

/// Map an `e_machine` value to a readable architecture name.
/// Covers the architectures commonly found in IoT firmware; unknown values
/// fall back to the raw numeric id so nothing is silently mislabeled.
fn machine_name(code: u16) -> &'static str {
    match code {
        0 => "None",
        2 => "SPARC",
        3 => "Intel 80386 (x86)",
        4 => "Motorola 68k",
        7 => "Intel i860",
        8 => "MIPS",
        20 => "PowerPC",
        21 => "PowerPC64",
        22 => "IBM S/390",
        40 => "ARM",
        42 => "Renesas SuperH",
        50 => "Intel IA-64",
        62 => "AMD x86-64",
        76 => "Axis CRIS",
        83 => "Atmel AVR32",
        88 => "Fujitsu FR-V",
        94 => "Tensilica Xtensa",
        140 => "Tilera TILEPro",
        183 => "AArch64 (ARM64)",
        188 => "Tilera TILE-Gx",
        189 => "Xilinx MicroBlaze",
        220 => "z/Architecture",
        243 => "RISC-V",
        249 => "MIPS nanoMIPS",
        _ => "Unknown architecture",
    }
}

fn elf_type_name(e_type: u16) -> &'static str {
    match e_type {
        header::ET_REL => "REL (relocatable object)",
        header::ET_EXEC => "EXEC (non-PIE executable)",
        header::ET_DYN => "DYN (PIE executable / shared object)",
        header::ET_CORE => "CORE (core dump)",
        _ => "Other",
    }
}

/// Cheap magic check used while walking directory trees.
pub fn is_elf(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[..4] == [0x7f, b'E', b'L', b'F']
}

/// Analyze a single file. Returns `Ok(None)` for files that are not ELF.
pub fn analyze_file(path: &Path) -> Result<Option<BinaryReport>> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    if !is_elf(&bytes) {
        return Ok(None);
    }
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let sha256 = hex_encode(&hasher.finalize());

    let elf = Elf::parse(&bytes).with_context(|| format!("parsing ELF {}", path.display()))?;
    Ok(Some(analyze_elf(path, &bytes, &elf, sha256)))
}

fn analyze_elf(path: &Path, bytes: &[u8], elf: &Elf, sha256: String) -> BinaryReport {
    let identity = ElfIdentity {
        class: if elf.is_64 {
            ElfClass::Elf64
        } else {
            ElfClass::Elf32
        },
        endianness: if elf.little_endian {
            Endianness::Little
        } else {
            Endianness::Big
        },
        machine: machine_name(elf.header.e_machine).to_string(),
        machine_code: elf.header.e_machine,
        elf_type: elf_type_name(elf.header.e_type).to_string(),
        entry: elf.entry,
    };

    // ---- symbol collection ------------------------------------------------
    // Imports are undefined symbols. lld keeps UND entries in .dynsym for
    // shared objects, but for PIE executables linked with `-z undefs` they
    // land only in the regular .symtab; fully static binaries have no
    // dynamic table at all. Collect the UND union of both tables so every
    // link style is covered. lld/llvm may tag imports as NOTYPE rather than
    // FUNC, so symbol type is deliberately not filtered on.
    let mut imported: Vec<String> = Vec::new();
    for sym in elf.dynsyms.iter() {
        if sym.st_shndx == SHN_UNDEF as usize {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    imported.push(name.to_string());
                }
            }
        }
    }
    for sym in elf.syms.iter() {
        if sym.st_shndx == SHN_UNDEF as usize {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    imported.push(name.to_string());
                }
            }
        }
    }
    imported.sort();
    imported.dedup();

    // Union of every symbol name visible in either table, for membership
    // checks (canary / fortify markers in static-linked binaries).
    let mut all_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    for sym in elf.dynsyms.iter() {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            all_names.insert(name.to_string());
        }
    }
    for sym in elf.syms.iter() {
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            all_names.insert(name.to_string());
        }
    }

    let is_relocatable = elf.header.e_type == header::ET_REL;
    let has_dynamic = elf.dynamic.is_some();
    // A fully stripped object keeps neither a dynamic nor a static symbol
    // table; in that case symbol-based checks can only answer "unknown".
    let no_symbol_tables = elf.dynsyms.is_empty() && elf.syms.is_empty();

    // ---- hardening checks -------------------------------------------------
    let pie = check_pie(elf, is_relocatable);
    let nx = check_nx(elf, is_relocatable);
    let relro = check_relro(elf, is_relocatable);
    let canary = check_canary(&all_names, is_relocatable, no_symbol_tables);
    let fortify = check_fortify(&all_names, has_dynamic, no_symbol_tables);
    let hardening = vec![pie, nx, relro, canary, fortify];

    // ---- FORTIFY call inventory -------------------------------------------
    let mut fortified_calls: Vec<FortifiedCall> = all_names
        .iter()
        .filter(|n| dangerdb::is_fortified_symbol(n))
        .map(|n| FortifiedCall {
            symbol: n.clone(),
            counterpart: dangerdb::fortified_counterpart(n).map(|s| s.to_string()),
        })
        .collect();
    fortified_calls.sort_by(|a, b| a.symbol.cmp(&b.symbol));

    // ---- dangerous imports ------------------------------------------------
    let mut dangerous_imports: Vec<DangerousImport> = Vec::new();
    for name in &imported {
        if let Some(entry) = dangerdb::lookup(name) {
            let chk = format!("__{name}_chk");
            let fortified = all_names.contains(&chk);
            dangerous_imports.push(DangerousImport {
                symbol: entry.name.to_string(),
                risk: entry.risk,
                rationale: entry.rationale.to_string(),
                fortified,
            });
        }
    }

    let needed_libraries = elf.libraries.iter().map(|s| s.to_string()).collect();
    let soname = elf.soname.map(|s| s.to_string());

    // Reference bytes so the signature stays honest if future checks need
    // section-level parsing (e.g. note-based ABI detection).
    let _ = bytes;

    BinaryReport {
        path: path.to_path_buf(),
        sha256,
        identity,
        hardening,
        needed_libraries,
        soname,
        dangerous_imports,
        fortified_calls,
        imported_symbols: imported,
    }
}

// ---------------------------------------------------------------------------
// Individual hardening checks
// ---------------------------------------------------------------------------

fn check_pie(elf: &Elf, is_relocatable: bool) -> HardeningCheck {
    use header::{ET_DYN, ET_EXEC, ET_REL};
    let (verdict, detail) = match elf.header.e_type {
        ET_DYN => {
            if elf.libraries.is_empty() && elf.program_headers.iter().any(|p| p.p_type == PT_LOAD) {
                (
                    Verdict::Enabled,
                    "ET_DYN with loadable segments: position-independent executable or shared object (ASLR compatible)".to_string(),
                )
            } else {
                (
                    Verdict::Enabled,
                    "ET_DYN shared object / PIE executable (ASLR compatible)".to_string(),
                )
            }
        }
        ET_EXEC => (
            Verdict::Disabled,
            "ET_EXEC: fixed load address, incompatible with full ASLR".to_string(),
        ),
        ET_REL => (
            Verdict::Unknown,
            "Relocatable object (.o/.ko): position independence is decided at the final link"
                .to_string(),
        ),
        other => (
            Verdict::Unknown,
            format!("Unrecognized ELF type {other}; PIE status undetermined"),
        ),
    };
    let _ = is_relocatable;
    HardeningCheck {
        id: "pie".to_string(),
        name: "Position Independent Executable (PIE/PIC)".to_string(),
        verdict,
        detail,
    }
}

fn check_nx(elf: &Elf, is_relocatable: bool) -> HardeningCheck {
    if is_relocatable {
        return HardeningCheck {
            id: "nx".to_string(),
            name: "NX stack / non-executable writable segments".to_string(),
            verdict: Verdict::Unknown,
            detail: "Relocatable object has no loadable segments; stack policy is set at link time"
                .to_string(),
        };
    }

    let gnu_stack = elf
        .program_headers
        .iter()
        .find(|p| p.p_type == PT_GNU_STACK);

    let mut wx_loads = Vec::new();
    for ph in elf.program_headers.iter() {
        if ph.p_type == PT_LOAD && (ph.p_flags & PF_W != 0) && (ph.p_flags & PF_X != 0) {
            wx_loads.push(ph.p_vaddr);
        }
    }

    let mut evidence = Vec::new();
    let verdict = match gnu_stack {
        Some(ph) if ph.p_flags & PF_X != 0 => {
            evidence.push("PT_GNU_STACK carries PF_X: stack is executable".to_string());
            Verdict::Disabled
        }
        Some(_) => {
            evidence.push("PT_GNU_STACK present without PF_X: non-executable stack".to_string());
            Verdict::Enabled
        }
        None => {
            // No PT_GNU_STACK is a legacy link; the loader's default depends
            // on kernel vintage and architecture, so report unknown rather
            // than guessing.
            evidence.push(
                "No PT_GNU_STACK header: stack executability falls back to loader/kernel default"
                    .to_string(),
            );
            Verdict::Unknown
        }
    };

    if !wx_loads.is_empty() {
        evidence.push(format!(
            "{} PT_LOAD segment(s) are simultaneously writable and executable (W^X violation)",
            wx_loads.len()
        ));
        // An explicitly executable loadable segment is stronger evidence than
        // a missing GNU_STACK marker.
        if verdict != Verdict::Disabled {
            return HardeningCheck {
                id: "nx".to_string(),
                name: "NX stack / non-executable writable segments".to_string(),
                verdict: Verdict::Disabled,
                detail: evidence.join("; "),
            };
        }
    }

    HardeningCheck {
        id: "nx".to_string(),
        name: "NX stack / non-executable writable segments".to_string(),
        verdict,
        detail: evidence.join("; "),
    }
}

fn check_relro(elf: &Elf, is_relocatable: bool) -> HardeningCheck {
    if is_relocatable {
        return HardeningCheck {
            id: "relro".to_string(),
            name: "GNU RELRO (GOT protection)".to_string(),
            verdict: Verdict::Unknown,
            detail: "Relocatable object has no dynamic section".to_string(),
        };
    }

    let has_relro_segment = elf.program_headers.iter().any(|p| p.p_type == PT_GNU_RELRO);

    let (bind_now, bind_evidence) = match &elf.dynamic {
        Some(dynamic) => {
            let flags = dynamic.info.flags;
            let flags_1 = dynamic.info.flags_1;
            let now = (flags & DF_BIND_NOW != 0) || (flags_1 & DF_1_NOW != 0);
            let mut bits = Vec::new();
            if flags & DF_BIND_NOW != 0 {
                bits.push("DT_FLAGS DF_BIND_NOW");
            }
            if flags_1 & DF_1_NOW != 0 {
                bits.push("DT_FLAGS_1 DF_1_NOW");
            }
            (now, bits.join(", "))
        }
        None => (false, String::new()),
    };

    let mut evidence = Vec::new();
    if has_relro_segment {
        evidence.push("PT_GNU_RELRO present".to_string());
    }
    if !bind_evidence.is_empty() {
        evidence.push(format!("full lazy-binding disabled via {bind_evidence}"));
    }

    let verdict = match (has_relro_segment, bind_now) {
        (true, true) => Verdict::Enabled,
        (true, false) => {
            evidence.push(
                "GOT is mapped read-only after relocations but lazy binding stays enabled"
                    .to_string(),
            );
            Verdict::Partial
        }
        // lld on MIPS/PPC emits BIND_NOW without a PT_GNU_RELRO segment:
        // lazy binding is off even though the GOT page is not marked RO.
        (false, true) => {
            evidence.push(
                "No PT_GNU_RELRO segment despite immediate binding; GOT page remains writable"
                    .to_string(),
            );
            Verdict::Partial
        }
        (false, false) => {
            if elf.dynamic.is_none() {
                evidence
                    .push("Statically linked: no dynamic relocation region to protect".to_string());
                Verdict::Unknown
            } else {
                evidence.push(
                    "Neither PT_GNU_RELRO nor BIND_NOW present; GOT is writable at runtime"
                        .to_string(),
                );
                Verdict::Disabled
            }
        }
    };

    HardeningCheck {
        id: "relro".to_string(),
        name: "GNU RELRO (GOT protection)".to_string(),
        verdict,
        detail: evidence.join("; "),
    }
}

fn check_canary(
    all_names: &std::collections::HashSet<String>,
    is_relocatable: bool,
    no_symbol_tables: bool,
) -> HardeningCheck {
    let present = CANARY_SYMBOLS.iter().any(|s| all_names.contains(*s));
    let verdict = if present {
        Verdict::Enabled
    } else if no_symbol_tables {
        Verdict::Unknown
    } else if is_relocatable {
        // Objects may reference the canary only after inlining decisions at
        // final link; absence is still informative but not conclusive.
        Verdict::Unknown
    } else {
        Verdict::Disabled
    };
    let detail = if present {
        "References __stack_chk_fail: stack canary checks emitted for vulnerable frames".to_string()
    } else if no_symbol_tables {
        "No symbol table available and canary marker not found; cannot rule out stack protection"
            .to_string()
    } else {
        "No reference to __stack_chk_fail/__stack_chk_fail_local: no stack canary detected"
            .to_string()
    };
    HardeningCheck {
        id: "stack-canary".to_string(),
        name: "Stack smashing protector (-fstack-protector)".to_string(),
        verdict,
        detail,
    }
}

fn check_fortify(
    all_names: &std::collections::HashSet<String>,
    has_dynamic: bool,
    no_symbol_tables: bool,
) -> HardeningCheck {
    let chk_calls: Vec<&String> = all_names
        .iter()
        .filter(|n| dangerdb::is_fortified_symbol(n))
        .collect();

    let verdict = if !chk_calls.is_empty() {
        Verdict::Enabled
    } else if no_symbol_tables {
        Verdict::Unknown
    } else {
        Verdict::Disabled
    };

    let detail = if !chk_calls.is_empty() {
        let mut names: Vec<&str> = chk_calls.iter().map(|s| s.as_str()).collect();
        names.sort();
        format!(
            "{} fortified libc entry point(s) imported (e.g. {}): compiled with _FORTIFY_SOURCE",
            names.len(),
            names.first().copied().unwrap_or("")
        )
    } else if no_symbol_tables {
        "No symbol table visible and no __*_chk markers found; FORTIFY status undetermined"
            .to_string()
    } else if has_dynamic {
        "No __*_chk symbols imported: _FORTIFY_SOURCE not enabled or no eligible call sites"
            .to_string()
    } else {
        "Static binary without __*_chk markers: FORTIFY not detected".to_string()
    };

    HardeningCheck {
        id: "fortify".to_string(),
        name: "FORTIFY_SOURCE (_*_chk bounded libc calls)".to_string(),
        verdict,
        detail,
    }
}

// ---------------------------------------------------------------------------
// Directory walking
// ---------------------------------------------------------------------------

pub struct WalkOutcome {
    pub report: ScanReport,
}

/// Recursively scan the given roots. Unreadable or unparseable files are
/// recorded in `parse_errors` instead of aborting the run, which matters for
/// firmware trees that contain intentionally corrupt blobs.
pub fn scan_roots(roots: &[PathBuf]) -> WalkOutcome {
    let mut binaries = Vec::new();
    let mut parse_errors = Vec::new();
    let mut skipped_non_elf = 0u64;
    let mut seen = std::collections::HashSet::new();

    for root in roots {
        let metadata = match fs::metadata(root) {
            Ok(m) => m,
            Err(e) => {
                parse_errors.push(ScanError {
                    path: root.clone(),
                    message: format!("cannot stat root: {e}"),
                });
                continue;
            }
        };

        if metadata.is_file() {
            visit_file(
                root,
                &mut binaries,
                &mut parse_errors,
                &mut skipped_non_elf,
                &mut seen,
            );
            continue;
        }

        for entry in walkdir::WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                visit_file(
                    entry.path(),
                    &mut binaries,
                    &mut parse_errors,
                    &mut skipped_non_elf,
                    &mut seen,
                );
            }
        }
    }

    binaries.sort_by(|a, b| a.path.cmp(&b.path));

    WalkOutcome {
        report: ScanReport {
            tool: env!("CARGO_PKG_NAME").to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            generated_at: now_rfc3339(),
            scan_roots: roots.to_vec(),
            binaries,
            parse_errors,
            skipped_non_elf,
        },
    }
}

fn visit_file(
    path: &Path,
    binaries: &mut Vec<BinaryReport>,
    parse_errors: &mut Vec<ScanError>,
    skipped_non_elf: &mut u64,
    seen: &mut std::collections::HashSet<PathBuf>,
) {
    let canonical = match path.canonicalize() {
        Ok(p) => p,
        Err(_) => path.to_path_buf(),
    };
    if !seen.insert(canonical) {
        return;
    }
    match analyze_file(path) {
        Ok(Some(report)) => binaries.push(report),
        Ok(None) => *skipped_non_elf += 1,
        Err(e) => parse_errors.push(ScanError {
            path: path.to_path_buf(),
            message: e.to_string(),
        }),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Public timestamp helper reused by the diff module.
pub fn now_rfc3339_public() -> String {
    now_rfc3339()
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
