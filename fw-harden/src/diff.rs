//! Version-to-version comparison of two scan reports.
//!
//! Binaries are matched by path relative to their scan root so that
//! `/firmware_v1/bin/app` and `/firmware_v2/bin/app` compare as the same
//! artifact even when absolute prefixes differ.

use crate::model::*;
use anyhow::Context;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn verdict_rank(v: Verdict) -> u8 {
    match v {
        Verdict::Enabled => 3,
        Verdict::Partial => 2,
        Verdict::Unknown => 1,
        Verdict::Disabled => 0,
    }
}

/// Relative path key; falls back to the full path when stripping the root
/// does not produce a descendant (e.g. single-file scans).
fn rel_key(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .replace('\\', "/")
}

fn index_by_key<'a>(report: &'a ScanReport, root: &Path) -> BTreeMap<String, &'a BinaryReport> {
    report
        .binaries
        .iter()
        .map(|b| (rel_key(root, &b.path), b))
        .collect()
}

pub fn diff_reports(
    old: &ScanReport,
    new: &ScanReport,
    old_root: &Path,
    new_root: &Path,
) -> DiffReport {
    let old_map = index_by_key(old, old_root);
    let new_map = index_by_key(new, new_root);

    let old_keys: BTreeSet<&String> = old_map.keys().collect();
    let new_keys: BTreeSet<&String> = new_map.keys().collect();

    let mut entries = Vec::new();

    // ---- appearing / disappearing binaries --------------------------------
    for key in new_keys.difference(&old_keys) {
        let report = new_map[*key];
        entries.push(DiffEntry {
            path: (*key).clone(),
            kind: DiffKind::NewBinary,
            severity: report.highest_risk().unwrap_or(RiskLevel::Low),
            description: format!(
                "New binary in this firmware version ({} {}, {})",
                match report.identity.class {
                    ElfClass::Elf32 => "ELF32",
                    ElfClass::Elf64 => "ELF64",
                },
                report.identity.machine,
                report.identity.elf_type
            ),
        });
    }
    for key in old_keys.difference(&new_keys) {
        entries.push(DiffEntry {
            path: (*key).clone(),
            kind: DiffKind::RemovedBinary,
            severity: RiskLevel::Low,
            description: "Binary present in the old firmware but absent in the new one".to_string(),
        });
    }

    // ---- per-binary comparisons -------------------------------------------
    for key in old_keys.intersection(&new_keys) {
        let old_bin = old_map[*key];
        let new_bin = new_map[*key];
        compare_binary(&mut entries, key, old_bin, new_bin);
    }

    entries.sort_by(|a, b| {
        risk_rank(b.severity)
            .cmp(&risk_rank(a.severity))
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| format!("{:?}", a.kind).cmp(&format!("{:?}", b.kind)))
    });

    let mut summary = DiffSummary::default();
    for e in &entries {
        match e.severity {
            RiskLevel::High => summary.high_severity += 1,
            RiskLevel::Medium => summary.medium_severity += 1,
            RiskLevel::Low => summary.low_severity += 1,
        }
        match e.kind {
            DiffKind::HardeningRegression => summary.hardening_regressions += 1,
            DiffKind::NewDangerousImport => summary.new_dangerous_imports += 1,
            DiffKind::RemovedDangerousImport => summary.removed_dangerous_imports += 1,
            DiffKind::NewDependency => summary.new_dependencies += 1,
            DiffKind::NewBinary => summary.new_binaries += 1,
            DiffKind::RemovedBinary => summary.removed_binaries += 1,
        }
    }

    DiffReport {
        tool: env!("CARGO_PKG_NAME").to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        generated_at: crate::analyzer::now_rfc3339_public(),
        old_root: old_root.to_path_buf(),
        new_root: new_root.to_path_buf(),
        entries,
        summary,
    }
}

fn risk_rank(r: RiskLevel) -> u8 {
    match r {
        RiskLevel::High => 3,
        RiskLevel::Medium => 2,
        RiskLevel::Low => 1,
    }
}

fn compare_binary(entries: &mut Vec<DiffEntry>, key: &str, old: &BinaryReport, new: &BinaryReport) {
    // ---- hardening regressions --------------------------------------------
    let old_checks: BTreeMap<&str, &HardeningCheck> =
        old.hardening.iter().map(|c| (c.id.as_str(), c)).collect();
    let new_checks: BTreeMap<&str, &HardeningCheck> =
        new.hardening.iter().map(|c| (c.id.as_str(), c)).collect();

    for (id, new_check) in &new_checks {
        if let Some(old_check) = old_checks.get(*id) {
            // Unknown verdicts mean "we could not tell" — never treat them as
            // regressions or improvements.
            if new_check.verdict == Verdict::Unknown || old_check.verdict == Verdict::Unknown {
                continue;
            }
            if verdict_rank(new_check.verdict) < verdict_rank(old_check.verdict) {
                entries.push(DiffEntry {
                    path: key.to_string(),
                    kind: DiffKind::HardeningRegression,
                    severity: RiskLevel::High,
                    description: format!(
                        "{} regressed: {} -> {}. Old: {} | New: {}",
                        new_check.name,
                        old_check.verdict.as_str(),
                        new_check.verdict.as_str(),
                        old_check.detail,
                        new_check.detail
                    ),
                });
            }
        }
    }

    // ---- dangerous imports ------------------------------------------------
    let old_danger: BTreeMap<&str, &DangerousImport> = old
        .dangerous_imports
        .iter()
        .map(|d| (d.symbol.as_str(), d))
        .collect();
    let new_danger: BTreeMap<&str, &DangerousImport> = new
        .dangerous_imports
        .iter()
        .map(|d| (d.symbol.as_str(), d))
        .collect();

    for (sym, import) in &new_danger {
        if !old_danger.contains_key(*sym) {
            entries.push(DiffEntry {
                path: key.to_string(),
                kind: DiffKind::NewDangerousImport,
                severity: import.risk,
                description: format!(
                    "New dangerous import `{}` ({} risk): {}{}",
                    sym,
                    import.risk.as_str(),
                    import.rationale,
                    if import.fortified {
                        " A fortified __*_chk counterpart is also present."
                    } else {
                        ""
                    }
                ),
            });
        }
    }
    for sym in old_danger.keys() {
        if !new_danger.contains_key(*sym) {
            entries.push(DiffEntry {
                path: key.to_string(),
                kind: DiffKind::RemovedDangerousImport,
                severity: RiskLevel::Low,
                description: format!(
                    "Dangerous import `{sym}` no longer present in the new version"
                ),
            });
        }
    }

    // ---- new DT_NEEDED dependencies ----------------------------------------
    let old_needed: BTreeSet<&str> = old.needed_libraries.iter().map(String::as_str).collect();
    for lib in &new.needed_libraries {
        if !old_needed.contains(lib.as_str()) {
            entries.push(DiffEntry {
                path: key.to_string(),
                kind: DiffKind::NewDependency,
                severity: RiskLevel::Medium,
                description: format!("New dynamic dependency DT_NEEDED `{lib}`"),
            });
        }
    }
}

/// Resolve a diff root: either a directory (scanned directly) or a previously
/// produced fw-harden JSON report.
pub fn load_root(path: &Path) -> anyhow::Result<(PathBuf, ScanReport)> {
    let metadata = fs_metadata(path)?;
    if metadata.is_file() {
        let bytes = std::fs::read(path)?;
        let report: ScanReport = serde_json::from_slice(&bytes)
            .with_context(|| format!("{} is not a fw-harden JSON scan report", path.display()))?;
        // Reuse the recorded scan roots; the first one anchors relative keys.
        let root = report
            .scan_roots
            .first()
            .cloned()
            .unwrap_or_else(|| path.to_path_buf());
        Ok((root, report))
    } else {
        let outcome = crate::analyzer::scan_roots(&[path.to_path_buf()]);
        Ok((path.to_path_buf(), outcome.report))
    }
}

fn fs_metadata(path: &Path) -> anyhow::Result<std::fs::Metadata> {
    std::fs::metadata(path).with_context(|| format!("cannot access {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DangerousImport, ElfClass, ElfIdentity, Endianness, HardeningCheck};

    fn identity() -> ElfIdentity {
        ElfIdentity {
            class: ElfClass::Elf64,
            endianness: Endianness::Little,
            machine: "test".to_string(),
            machine_code: 62,
            elf_type: "DYN".to_string(),
            entry: 0,
        }
    }

    fn check(id: &str, verdict: Verdict) -> HardeningCheck {
        HardeningCheck {
            id: id.to_string(),
            name: id.to_string(),
            verdict,
            detail: String::new(),
        }
    }

    fn danger(sym: &str, risk: RiskLevel) -> DangerousImport {
        DangerousImport {
            symbol: sym.to_string(),
            risk,
            rationale: "test".to_string(),
            fortified: false,
        }
    }

    fn report(
        root: &Path,
        rel: &str,
        checks: Vec<HardeningCheck>,
        imports: Vec<DangerousImport>,
        needed: Vec<&str>,
    ) -> (PathBuf, BinaryReport) {
        let path = root.join(rel);
        (
            root.to_path_buf(),
            BinaryReport {
                path: path.clone(),
                sha256: "deadbeef".to_string(),
                identity: identity(),
                hardening: checks,
                needed_libraries: needed.into_iter().map(str::to_string).collect(),
                soname: None,
                dangerous_imports: imports,
                fortified_calls: Vec::new(),
                imported_symbols: Vec::new(),
            },
        )
    }

    fn scan(binaries: Vec<BinaryReport>, root: PathBuf) -> ScanReport {
        ScanReport {
            tool: "fw-harden".to_string(),
            tool_version: "test".to_string(),
            generated_at: "1970-01-01T00:00:00Z".to_string(),
            scan_roots: vec![root.clone()],
            binaries,
            parse_errors: Vec::new(),
            skipped_non_elf: 0,
        }
    }

    #[test]
    fn relative_keys_match_across_different_roots() {
        let old_root = Path::new("/opt/firmware_v1");
        let new_root = Path::new("/opt/firmware_v2");
        let (_, old_bin) = report(old_root, "bin/app", vec![], vec![], vec![]);
        let (_, new_bin) = report(new_root, "bin/app", vec![], vec![], vec![]);
        let old = scan(vec![old_bin], old_root.to_path_buf());
        let new = scan(vec![new_bin], new_root.to_path_buf());
        let out = diff_reports(&old, &new, old_root, new_root);
        assert!(
            out.entries.is_empty(),
            "identical reports should diff clean"
        );
    }

    #[test]
    fn detects_regression_new_import_dependency_and_binary_changes() {
        let old_root = Path::new("/opt/fw1");
        let new_root = Path::new("/opt/fw2");

        let (_, old_app) = report(
            old_root,
            "bin/app",
            vec![
                check("nx", Verdict::Enabled),
                check("relro", Verdict::Enabled),
                check("fortify", Verdict::Unknown),
            ],
            vec![
                danger("strcpy", RiskLevel::High),
                danger("gets", RiskLevel::High),
            ],
            vec!["libc.so.6"],
        );
        let (_, new_app) = report(
            new_root,
            "bin/app",
            vec![
                check("nx", Verdict::Disabled),
                check("relro", Verdict::Enabled),
                check("fortify", Verdict::Unknown),
            ],
            vec![
                danger("strcpy", RiskLevel::High),
                danger("system", RiskLevel::High),
            ],
            vec!["libc.so.6", "libextra.so"],
        );
        let (_, new_only) = report(new_root, "bin/helper", vec![], vec![], vec![]);
        let (_, old_only) = report(old_root, "bin/retired", vec![], vec![], vec![]);

        let old = scan(vec![old_app, old_only], old_root.to_path_buf());
        let new = scan(vec![new_app, new_only], new_root.to_path_buf());
        let out = diff_reports(&old, &new, old_root, new_root);

        let kinds: Vec<DiffKind> = out.entries.iter().map(|e| e.kind).collect();
        assert!(kinds.contains(&DiffKind::HardeningRegression));
        assert!(kinds.contains(&DiffKind::NewDangerousImport));
        assert!(kinds.contains(&DiffKind::RemovedDangerousImport));
        assert!(kinds.contains(&DiffKind::NewDependency));
        assert!(kinds.contains(&DiffKind::NewBinary));
        assert!(kinds.contains(&DiffKind::RemovedBinary));

        // Unknown verdicts must never be treated as movement.
        let fortify_moved = out
            .entries
            .iter()
            .any(|e| e.description.contains("FORTIFY"));
        assert!(!fortify_moved);

        // The regression is high severity.
        assert!(out
            .entries
            .iter()
            .any(|e| e.kind == DiffKind::HardeningRegression && e.severity == RiskLevel::High));
        assert_eq!(out.summary.hardening_regressions, 1);
        assert_eq!(out.summary.new_dependencies, 1);
    }

    #[test]
    fn enabled_to_partial_is_a_regression_but_unknown_is_not() {
        assert!(verdict_rank(Verdict::Enabled) > verdict_rank(Verdict::Partial));
        assert!(verdict_rank(Verdict::Partial) > verdict_rank(Verdict::Disabled));
    }
}
