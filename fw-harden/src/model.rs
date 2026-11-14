//! Serde data models for scan results, findings and diffs.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Hardening check verdict. `Unknown` is used when the ELF layout does not
/// carry enough information to decide (e.g. stripped section headers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Enabled,
    Disabled,
    Partial,
    Unknown,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Enabled => "enabled",
            Verdict::Disabled => "disabled",
            Verdict::Partial => "partial",
            Verdict::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    High,
    Medium,
    Low,
}

impl RiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            RiskLevel::High => "high",
            RiskLevel::Medium => "medium",
            RiskLevel::Low => "low",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ElfClass {
    Elf32,
    Elf64,
}

/// One hardening dimension for one binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningCheck {
    /// Stable machine-readable id, e.g. "pie", "nx", "relro", "stack-canary", "fortify".
    pub id: String,
    pub name: String,
    pub verdict: Verdict,
    /// Human-readable evidence extracted from the ELF (flags, segments, symbols).
    pub detail: String,
}

/// A dangerous imported function referenced by the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DangerousImport {
    pub symbol: String,
    pub risk: RiskLevel,
    pub rationale: String,
    /// True when a fortified replacement (`__<name>_chk`) is also imported,
    /// which usually means the call site was compiled with `_FORTIFY_SOURCE`.
    pub fortified: bool,
}

/// A `__*_chk` style fortified libc entry point imported by the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FortifiedCall {
    pub symbol: String,
    /// The un-fortified counterpart when known, e.g. `memcpy` for `__memcpy_chk`.
    pub counterpart: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfIdentity {
    pub class: ElfClass,
    pub endianness: Endianness,
    pub machine: String,
    pub machine_code: u16,
    pub elf_type: String,
    pub entry: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanError {
    pub path: PathBuf,
    pub message: String,
}

/// Full audit result for one ELF file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryReport {
    pub path: PathBuf,
    pub sha256: String,
    pub identity: ElfIdentity,
    pub hardening: Vec<HardeningCheck>,
    pub needed_libraries: Vec<String>,
    pub soname: Option<String>,
    pub dangerous_imports: Vec<DangerousImport>,
    pub fortified_calls: Vec<FortifiedCall>,
    /// All undefined dynamic symbols (the import table), sorted and de-duplicated.
    pub imported_symbols: Vec<String>,
}

impl BinaryReport {
    pub fn check(&self, id: &str) -> Option<&HardeningCheck> {
        self.hardening.iter().find(|c| c.id == id)
    }

    pub fn highest_risk(&self) -> Option<RiskLevel> {
        self.dangerous_imports
            .iter()
            .map(|d| d.risk)
            .max_by_key(|r| match r {
                RiskLevel::High => 3,
                RiskLevel::Medium => 2,
                RiskLevel::Low => 1,
            })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub tool: String,
    pub tool_version: String,
    pub generated_at: String,
    /// Roots that were walked.
    pub scan_roots: Vec<PathBuf>,
    pub binaries: Vec<BinaryReport>,
    pub parse_errors: Vec<ScanError>,
    /// Files seen but skipped because they are not ELF.
    pub skipped_non_elf: u64,
}

/// A single difference entry in a version-to-version comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    pub path: String,
    pub kind: DiffKind,
    pub severity: RiskLevel,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiffKind {
    /// Hardening verdict got weaker (enabled -> partial/disabled ...).
    HardeningRegression,
    /// New high/medium risk imported function.
    NewDangerousImport,
    /// A previously used dangerous function disappeared (informational).
    RemovedDangerousImport,
    /// New DT_NEEDED dependency.
    NewDependency,
    /// New executable/shared object present only in the new firmware.
    NewBinary,
    /// Binary present in old firmware but missing in the new one.
    RemovedBinary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    pub tool: String,
    pub tool_version: String,
    pub generated_at: String,
    pub old_root: PathBuf,
    pub new_root: PathBuf,
    pub entries: Vec<DiffEntry>,
    pub summary: DiffSummary,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiffSummary {
    pub hardening_regressions: usize,
    pub new_dangerous_imports: usize,
    pub removed_dangerous_imports: usize,
    pub new_dependencies: usize,
    pub new_binaries: usize,
    pub removed_binaries: usize,
    pub high_severity: usize,
    pub medium_severity: usize,
    pub low_severity: usize,
}
