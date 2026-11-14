//! End-to-end tests against the clang/lld-built sample firmware trees.
//!
//! These run only when `samples/build.sh` has produced the trees (or the
//! FW_HARDEN_SAMPLES env var points at them), so a plain `cargo test`
//! stays green on a clean checkout without LLVM installed.

use fw_harden::diff;
use fw_harden::model::{DiffKind, RiskLevel, Verdict};
use std::path::PathBuf;

fn samples_root() -> Option<PathBuf> {
    if let Ok(custom) = std::env::var("FW_HARDEN_SAMPLES") {
        let p = PathBuf::from(custom);
        return p.is_dir().then_some(p);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let p = manifest.join("samples/build");
    p.is_dir().then_some(p)
}

fn verdict(bin: &fw_harden::model::BinaryReport, id: &str) -> Verdict {
    bin.check(id).unwrap().verdict
}

#[test]
fn sample_firmware_scan_covers_widths_and_endiannesses() {
    let Some(root) = samples_root() else {
        eprintln!("skipping: sample firmware not built (run samples/build.sh)");
        return;
    };
    let v1 = root.join("firmware_v1");
    let outcome = fw_harden::analyzer::scan_roots(&[v1]);
    assert!(outcome.report.parse_errors.is_empty(), "no parse errors");
    assert!(
        outcome.report.binaries.len() >= 36,
        "all architectures present"
    );
    assert_eq!(outcome.report.skipped_non_elf, 2, "json/txt skipped");

    let mut classes = std::collections::HashSet::new();
    let mut endians = std::collections::HashSet::new();
    let mut machines = std::collections::HashSet::new();
    for b in &outcome.report.binaries {
        classes.insert(b.identity.class);
        endians.insert(b.identity.endianness);
        machines.insert(b.identity.machine_code);
    }
    use fw_harden::model::{ElfClass, Endianness};
    assert_eq!(
        classes,
        [ElfClass::Elf32, ElfClass::Elf64].into_iter().collect()
    );
    assert_eq!(
        endians,
        [Endianness::Little, Endianness::Big].into_iter().collect()
    );
    // x86_64(62), MIPS(8), PowerPC(20), ARM(40), RISC-V(243), AArch64(183) ...
    assert!(machines.len() >= 8, "found machines: {machines:?}");
}

#[test]
fn sample_v1_legacy_flasher_is_non_pie_with_executable_stack() {
    let Some(root) = samples_root() else {
        return;
    };
    let flasher = root.join("firmware_v1/arch/x86_64/legacy-flasher");
    let report = fw_harden::analyzer::analyze_file(&flasher)
        .unwrap()
        .expect("legacy-flasher is ELF");
    assert_eq!(verdict(&report, "pie"), Verdict::Disabled);
    assert_eq!(verdict(&report, "nx"), Verdict::Disabled);
}

#[test]
fn sample_mips_relro_quirk_is_reported_as_partial_when_bindnow_only() {
    let Some(root) = samples_root() else {
        return;
    };
    // v2 libmgmt on MIPS: full flags but lld omits PT_GNU_RELRO.
    let lib = root.join("firmware_v2/arch/mips32-be/libmgmt.so.1");
    let report = fw_harden::analyzer::analyze_file(&lib).unwrap().unwrap();
    assert_eq!(verdict(&report, "relro"), Verdict::Partial);
    assert!(report
        .check("relro")
        .unwrap()
        .detail
        .contains("No PT_GNU_RELRO"));
}

#[test]
fn sample_diff_flags_gatewayd_regressions_and_popen_across_architectures() {
    let Some(root) = samples_root() else {
        return;
    };
    let old_dir = root.join("firmware_v1");
    let new_dir = root.join("firmware_v2");
    let (old_root, old_report) = diff::load_root(&old_dir).unwrap();
    let (new_root, new_report) = diff::load_root(&new_dir).unwrap();
    let out = diff::diff_reports(&old_report, &new_report, &old_root, &new_root);

    // Every architecture's gatewayd loses NX/canary/RELRO and gains popen.
    let gateway_paths: std::collections::HashSet<String> =
        out.entries.iter().map(|e| e.path.clone()).collect();
    assert!(gateway_paths
        .iter()
        .any(|p| p.contains("mips32-be/gatewayd")));
    assert!(gateway_paths.iter().any(|p| p.contains("riscv32/gatewayd")));

    let popen = out
        .entries
        .iter()
        .filter(|e| e.kind == DiffKind::NewDangerousImport && e.description.contains("popen"))
        .count();
    assert_eq!(popen, 12, "one popen regression per architecture");
    assert!(out.entries.iter().all(|e| match e.kind {
        DiffKind::HardeningRegression => e.severity == RiskLevel::High,
        _ => true,
    }));

    // New dependency and binary entries for libwatchdog.
    assert!(out
        .entries
        .iter()
        .any(|e| { e.kind == DiffKind::NewDependency && e.description.contains("libwatchdog") }));
    assert!(out
        .entries
        .iter()
        .any(|e| { e.kind == DiffKind::NewBinary && e.path.contains("libwatchdog") }));
    // factory-tool removed.
    assert!(out
        .entries
        .iter()
        .any(|e| { e.kind == DiffKind::RemovedBinary && e.path.contains("factory-tool") }));
    assert!(out.summary.hardening_regressions >= 30);
}

#[test]
fn diff_accepts_prior_json_reports_as_inputs() {
    let Some(root) = samples_root() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let old_json = dir.path().join("v1.json");
    let new_json = dir.path().join("v2.json");

    let old = fw_harden::analyzer::scan_roots(&[root.join("firmware_v1")]);
    let new = fw_harden::analyzer::scan_roots(&[root.join("firmware_v2")]);
    std::fs::write(&old_json, serde_json::to_vec(&old.report).unwrap()).unwrap();
    std::fs::write(&new_json, serde_json::to_vec(&new.report).unwrap()).unwrap();

    let (_, loaded_old) = diff::load_root(&old_json).unwrap();
    let (_, loaded_new) = diff::load_root(&new_json).unwrap();
    assert_eq!(loaded_old.binaries.len(), old.report.binaries.len());
    let out = diff::diff_reports(
        &loaded_old,
        &loaded_new,
        &root.join("firmware_v1"),
        &root.join("firmware_v2"),
    );
    assert!(!out.entries.is_empty());
}

#[test]
fn stripped_static_agentd_uses_unknown_not_false_disabled() {
    let Some(root) = samples_root() else {
        return;
    };
    let agentd = root.join("firmware_v1/arch/aarch64/agentd");
    let report = fw_harden::analyzer::analyze_file(&agentd).unwrap().unwrap();
    assert_eq!(verdict(&report, "stack-canary"), Verdict::Unknown);
    assert_eq!(verdict(&report, "fortify"), Verdict::Unknown);
}
