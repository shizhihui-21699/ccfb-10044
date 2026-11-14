//! SARIF v2.1.0 output.
//!
//! Two rule families:
//! * `FW-HARD-*`  — hardening weaknesses found in a scan
//! * `FW-DIFF-*`  — regressions and new risks found in a version diff
//!
//! The schema is emitted as plain serde structs rather than a full SARIF
//! crate; only the subset understood by GitHub code scanning and common
//! SARIF validators is used.

use crate::model::*;
use serde::Serialize;
use std::path::Path;

const SARIF_VERSION: &str = "2.1.0";
const SARIF_SCHEMA: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json";

#[derive(Serialize)]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<Run>,
}

#[derive(Serialize)]
pub struct Run {
    pub tool: Tool,
    pub invocations: Vec<Invocation>,
    pub results: Vec<ResultEntry>,
    #[serde(rename = "originalUriBaseIds", skip_serializing_if = "Option::is_none")]
    pub original_uri_base_ids: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub struct Tool {
    pub driver: Driver,
}

#[derive(Serialize)]
pub struct Driver {
    pub name: String,
    #[serde(rename = "fullName")]
    pub full_name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    pub rules: Vec<Rule>,
}

#[derive(Serialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: MultilingualText,
    #[serde(rename = "fullDescription")]
    pub full_description: MultilingualText,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: DefaultConfiguration,
}

#[derive(Serialize)]
pub struct MultilingualText {
    pub text: String,
}

#[derive(Serialize)]
pub struct DefaultConfiguration {
    pub level: String,
}

#[derive(Serialize)]
pub struct Invocation {
    #[serde(rename = "executionSuccessful")]
    pub execution_successful: bool,
}

#[derive(Serialize)]
pub struct ResultEntry {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: MultilingualText,
    pub locations: Vec<Location>,
    #[serde(
        rename = "partialFingerprints",
        skip_serializing_if = "Option::is_none"
    )]
    pub partial_fingerprints: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Serialize)]
pub struct Location {
    #[serde(rename = "physicalLocation")]
    pub physical_location: PhysicalLocation,
}

#[derive(Serialize)]
pub struct PhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: ArtifactLocation,
}

#[derive(Serialize)]
pub struct ArtifactLocation {
    pub uri: String,
}

fn level_for_risk(risk: RiskLevel) -> &'static str {
    match risk {
        RiskLevel::High => "error",
        RiskLevel::Medium => "warning",
        RiskLevel::Low => "note",
    }
}

fn level_for_verdict(v: Verdict) -> &'static str {
    match v {
        Verdict::Disabled => "error",
        Verdict::Partial => "warning",
        Verdict::Unknown => "note",
        Verdict::Enabled => "none",
    }
}

fn rule(id: &str, name: &str, short: &str, full: &str, level: &str) -> Rule {
    Rule {
        id: id.to_string(),
        name: name.to_string(),
        short_description: MultilingualText {
            text: short.to_string(),
        },
        full_description: MultilingualText {
            text: full.to_string(),
        },
        default_configuration: DefaultConfiguration {
            level: level.to_string(),
        },
    }
}

fn hardening_rules() -> Vec<Rule> {
    vec![
        rule(
            "FW-HARD-PIE",
            "NoPIE",
            "Binary is built without position independence",
            "ET_EXEC binaries load at a fixed address and cannot benefit from full ASLR. Rebuild with -fPIE/-fpie (and -pie at link time).",
            "error",
        ),
        rule(
            "FW-HARD-NX",
            "ExecutableStackOrWX",
            "Executable stack or writable+executable segment",
            "An executable PT_GNU_STACK or a writable/executable PT_LOAD makes shellcode injection straightforward. Relink with -z noexecstack and remove executable writable segments.",
            "error",
        ),
        rule(
            "FW-HARD-RELRO",
            "WeakRELRO",
            "GOT is not fully protected by RELRO/BIND_NOW",
            "Partial or missing RELRO leaves the GOT writable (and lazily bound), enabling GOT overwrite attacks. Rebuild with -Wl,-z,relro,-z,now.",
            "warning",
        ),
        rule(
            "FW-HARD-CANARY",
            "NoStackCanary",
            "No stack smashing protector detected",
            "The binary shows no reference to __stack_chk_fail, so stack buffer overflows cannot be caught at runtime. Rebuild vulnerable translation units with -fstack-protector-strong.",
            "warning",
        ),
        rule(
            "FW-HARD-FORTIFY",
            "NoFORTIFY",
            "_FORTIFY_SOURCE not detected",
            "No fortified __*_chk libc entry points are imported. Rebuild with -O2 -D_FORTIFY_SOURCE=2 to gain runtime bounds checks on string/memory operations.",
            "warning",
        ),
        rule(
            "FW-HARD-DANGER",
            "DangerousImport",
            "Import of a historically dangerous libc function",
            "The binary imports a function with a long history of memory-safety or command-injection misuse. Review call sites and prefer the bounded or fortified replacement.",
            "warning",
        ),
    ]
}

fn diff_rules() -> Vec<Rule> {
    vec![
        rule(
            "FW-DIFF-REGRESSION",
            "HardeningRegression",
            "Hardening protection regressed between firmware versions",
            "A hardening dimension that was enabled (or stronger) in the old version is weaker in the new version.",
            "error",
        ),
        rule(
            "FW-DIFF-NEW-DANGER",
            "NewDangerousImport",
            "New dangerous function import",
            "The new firmware version imports a dangerous function that the old version did not.",
            "warning",
        ),
        rule(
            "FW-DIFF-NEW-DEP",
            "NewDependency",
            "New DT_NEEDED dynamic dependency",
            "A new shared library dependency was introduced and should be reviewed for attack surface.",
            "warning",
        ),
        rule(
            "FW-DIFF-NEW-BINARY",
            "NewBinary",
            "New executable or shared library",
            "A previously absent ELF binary ships in the new firmware version.",
            "note",
        ),
        rule(
            "FW-DIFF-REMOVED-BINARY",
            "RemovedBinary",
            "Binary removed from firmware",
            "An ELF binary present in the old version is absent from the new one.",
            "note",
        ),
        rule(
            "FW-DIFF-REMOVED-DANGER",
            "DangerousImportRemoved",
            "Dangerous import removed",
            "A previously imported dangerous function is no longer imported.",
            "note",
        ),
    ]
}

fn uri_for(path: &Path) -> String {
    // SARIF URIs use forward slashes; keep firmware-relative paths readable.
    path.to_string_lossy().replace('\\', "/")
}

/// Build SARIF for a full scan. Enabled checks do not produce results;
/// `unknown` verdicts are emitted as notes for auditability.
pub fn scan_to_sarif(report: &ScanReport) -> SarifLog {
    let mut results = Vec::new();

    for bin in &report.binaries {
        let loc = || {
            vec![Location {
                physical_location: PhysicalLocation {
                    artifact_location: ArtifactLocation {
                        uri: uri_for(&bin.path),
                    },
                },
            }]
        };
        let fingerprint = |key: &str| {
            let mut map = serde_json::Map::new();
            map.insert(
                "binaryHashV1".to_string(),
                serde_json::Value::String(format!("{}:{}", bin.sha256, key)),
            );
            Some(map)
        };

        for check in &bin.hardening {
            let (rule_id, level) = match check.id.as_str() {
                "pie" => ("FW-HARD-PIE", level_for_verdict(check.verdict)),
                "nx" => ("FW-HARD-NX", level_for_verdict(check.verdict)),
                "relro" => ("FW-HARD-RELRO", level_for_verdict(check.verdict)),
                "stack-canary" => ("FW-HARD-CANARY", level_for_verdict(check.verdict)),
                "fortify" => ("FW-HARD-FORTIFY", level_for_verdict(check.verdict)),
                _ => continue,
            };
            if level == "none" {
                continue;
            }
            results.push(ResultEntry {
                rule_id: rule_id.to_string(),
                level: level.to_string(),
                message: MultilingualText {
                    text: format!("{}: {}", check.name, check.detail),
                },
                locations: loc(),
                partial_fingerprints: fingerprint(check.id.as_str()),
            });
        }

        for danger in &bin.dangerous_imports {
            results.push(ResultEntry {
                rule_id: "FW-HARD-DANGER".to_string(),
                level: level_for_risk(danger.risk).to_string(),
                message: MultilingualText {
                    text: format!(
                        "`{}` import ({} risk): {}{}",
                        danger.symbol,
                        danger.risk.as_str(),
                        danger.rationale,
                        if danger.fortified {
                            " Fortified counterpart detected."
                        } else {
                            ""
                        }
                    ),
                },
                locations: loc(),
                partial_fingerprints: fingerprint(&format!("danger:{}", danger.symbol)),
            });
        }
    }

    SarifLog {
        schema: SARIF_SCHEMA.to_string(),
        version: SARIF_VERSION.to_string(),
        runs: vec![Run {
            tool: Tool {
                driver: Driver {
                    name: "fw-harden".to_string(),
                    full_name: "Firmware ELF hardening auditor".to_string(),
                    version: report.tool_version.clone(),
                    information_uri: "https://example.invalid/fw-harden".to_string(),
                    rules: hardening_rules(),
                },
            },
            invocations: vec![Invocation {
                execution_successful: true,
            }],
            results,
            original_uri_base_ids: None,
        }],
    }
}

pub fn diff_to_sarif(diff: &DiffReport) -> SarifLog {
    let mut results = Vec::new();
    for entry in &diff.entries {
        let (rule_id, level) = match entry.kind {
            DiffKind::HardeningRegression => ("FW-DIFF-REGRESSION", level_for_risk(entry.severity)),
            DiffKind::NewDangerousImport => ("FW-DIFF-NEW-DANGER", level_for_risk(entry.severity)),
            DiffKind::RemovedDangerousImport => {
                ("FW-DIFF-REMOVED-DANGER", level_for_risk(entry.severity))
            }
            DiffKind::NewDependency => ("FW-DIFF-NEW-DEP", level_for_risk(entry.severity)),
            DiffKind::NewBinary => ("FW-DIFF-NEW-BINARY", level_for_risk(entry.severity)),
            DiffKind::RemovedBinary => ("FW-DIFF-REMOVED-BINARY", level_for_risk(entry.severity)),
        };
        results.push(ResultEntry {
            rule_id: rule_id.to_string(),
            level: level.to_string(),
            message: MultilingualText {
                text: entry.description.clone(),
            },
            locations: vec![Location {
                physical_location: PhysicalLocation {
                    artifact_location: ArtifactLocation {
                        uri: entry.path.replace('\\', "/"),
                    },
                },
            }],
            partial_fingerprints: None,
        });
    }

    SarifLog {
        schema: SARIF_SCHEMA.to_string(),
        version: SARIF_VERSION.to_string(),
        runs: vec![Run {
            tool: Tool {
                driver: Driver {
                    name: "fw-harden".to_string(),
                    full_name: "Firmware ELF hardening auditor".to_string(),
                    version: diff.tool_version.clone(),
                    information_uri: "https://example.invalid/fw-harden".to_string(),
                    rules: diff_rules(),
                },
            },
            invocations: vec![Invocation {
                execution_successful: true,
            }],
            results,
            original_uri_base_ids: Some(serde_json::json!({
                "OLDROOT": { "uri": uri_for(&diff.old_root) },
                "NEWROOT": { "uri": uri_for(&diff.new_root) },
            })),
        }],
    }
}
