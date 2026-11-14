//! SARIF serialization tests: rule/result consistency and JSON round-trip.

use fw_harden::model::*;
use fw_harden::sarif;

fn identity() -> ElfIdentity {
    ElfIdentity {
        class: ElfClass::Elf64,
        endianness: Endianness::Little,
        machine: "x86-64".into(),
        machine_code: 62,
        elf_type: "DYN".into(),
        entry: 0,
    }
}

fn sample_report() -> ScanReport {
    let hardening = vec![
        HardeningCheck {
            id: "pie".into(),
            name: "PIE".into(),
            verdict: Verdict::Enabled,
            detail: "ok".into(),
        },
        HardeningCheck {
            id: "nx".into(),
            name: "NX".into(),
            verdict: Verdict::Disabled,
            detail: "exec stack".into(),
        },
        HardeningCheck {
            id: "relro".into(),
            name: "RELRO".into(),
            verdict: Verdict::Partial,
            detail: "lazy".into(),
        },
        HardeningCheck {
            id: "stack-canary".into(),
            name: "canary".into(),
            verdict: Verdict::Unknown,
            detail: "stripped".into(),
        },
        HardeningCheck {
            id: "fortify".into(),
            name: "FORTIFY".into(),
            verdict: Verdict::Disabled,
            detail: "none".into(),
        },
    ];
    let dangerous = vec![DangerousImport {
        symbol: "gets".into(),
        risk: RiskLevel::High,
        rationale: "unsafe".into(),
        fortified: false,
    }];
    ScanReport {
        tool: "fw-harden".into(),
        tool_version: "test".into(),
        generated_at: "1970-01-01T00:00:00Z".into(),
        scan_roots: vec![],
        binaries: vec![BinaryReport {
            path: "/fw/bin/app".into(),
            sha256: "abc".into(),
            identity: identity(),
            hardening,
            needed_libraries: vec!["libc.so.6".into()],
            soname: None,
            dangerous_imports: dangerous,
            fortified_calls: vec![],
            imported_symbols: vec!["gets".into()],
        }],
        parse_errors: vec![],
        skipped_non_elf: 0,
    }
}

#[test]
fn scan_sarif_links_every_result_to_a_declared_rule() {
    let log = sarif::scan_to_sarif(&sample_report());
    assert_eq!(log.version, "2.1.0");
    let run = &log.runs[0];
    assert!(run.invocations[0].execution_successful);
    let rule_ids: std::collections::HashSet<&str> = run
        .tool
        .driver
        .rules
        .iter()
        .map(|r| r.id.as_str())
        .collect();
    assert!(!run.results.is_empty());
    for result in &run.results {
        assert!(rule_ids.contains(result.rule_id.as_str()));
        assert!(!result.message.text.is_empty());
        let uri = &result.locations[0].physical_location.artifact_location.uri;
        assert!(uri.contains("app"));
    }
    // Enabled PIE must not produce a finding.
    assert!(!run.results.iter().any(|r| r.rule_id == "FW-HARD-PIE"));
    // Disabled NX is error level, partial RELRO a warning, unknown canary a note.
    let level = |id: &str| {
        run.results
            .iter()
            .find(|r| r.rule_id == id)
            .map(|r| r.level.as_str())
            .unwrap()
    };
    assert_eq!(level("FW-HARD-NX"), "error");
    assert_eq!(level("FW-HARD-RELRO"), "warning");
    assert_eq!(level("FW-HARD-CANARY"), "note");
}

#[test]
fn sarif_json_round_trips_and_uses_camel_case_fingerprints() {
    let log = sarif::scan_to_sarif(&sample_report());
    let json = serde_json::to_string(&log).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["version"], "2.1.0");
    let first = &parsed["runs"][0]["results"][0];
    assert!(
        first.get("partialFingerprints").is_some(),
        "SARIF property must be camelCase partialFingerprints"
    );
    assert!(first.get("partial_fingerprints").is_none());
}

#[test]
fn diff_sarif_maps_kinds_to_distinct_rules() {
    let diff = DiffReport {
        tool: "fw-harden".into(),
        tool_version: "test".into(),
        generated_at: "1970-01-01T00:00:00Z".into(),
        old_root: "/old".into(),
        new_root: "/new".into(),
        entries: vec![
            DiffEntry {
                path: "bin/app".into(),
                kind: DiffKind::HardeningRegression,
                severity: RiskLevel::High,
                description: "nx regressed".into(),
            },
            DiffEntry {
                path: "bin/app".into(),
                kind: DiffKind::NewDangerousImport,
                severity: RiskLevel::Medium,
                description: "new popen".into(),
            },
            DiffEntry {
                path: "bin/app".into(),
                kind: DiffKind::NewDependency,
                severity: RiskLevel::Medium,
                description: "new lib".into(),
            },
        ],
        summary: DiffSummary::default(),
    };
    let log = sarif::diff_to_sarif(&diff);
    let rule_ids: std::collections::HashSet<&str> = log.runs[0]
        .tool
        .driver
        .rules
        .iter()
        .map(|r| r.id.as_str())
        .collect();
    for result in &log.runs[0].results {
        assert!(rule_ids.contains(result.rule_id.as_str()));
    }
    let levels: Vec<&str> = log.runs[0]
        .results
        .iter()
        .map(|r| r.level.as_str())
        .collect();
    assert!(levels.contains(&"error"));
    assert!(levels.contains(&"warning"));
    assert!(log.runs[0].original_uri_base_ids.is_some());
}
