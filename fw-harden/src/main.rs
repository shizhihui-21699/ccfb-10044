use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use fw_harden::analyzer;
use fw_harden::diff;
use fw_harden::model::{RiskLevel, Verdict};
use fw_harden::sarif;
use std::io::Write;
use std::path::{Path, PathBuf};

/// CI gating policy: when to exit non-zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum FailOn {
    /// Always exit 0 on a successful scan/diff (findings stay in the reports).
    Never,
    /// Fail only on high-severity findings / disabled hardening.
    #[default]
    High,
    /// Fail on any finding, including medium/low and partial/unknown states.
    AnyFinding,
}

/// Firmware ELF hardening auditor.
///
/// Scans firmware trees for ELF executables and shared libraries, reports
/// PIE/NX/RELRO/stack-canary/FORTIFY status, dangerous imported functions,
/// and compares two firmware versions for regressions. Emits JSON and SARIF
/// v2.1.0 for CI integration.
#[derive(Parser)]
#[command(name = "fw-harden", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan one or more directories/files and emit a hardening report.
    Scan {
        /// Firmware root directories or individual ELF files.
        #[arg(required = true, num_args = 1..)]
        paths: Vec<PathBuf>,

        /// Write JSON report here instead of stdout.
        #[arg(long, value_name = "FILE")]
        json: Option<PathBuf>,

        /// Also write a SARIF v2.1.0 report to this file.
        #[arg(long, value_name = "FILE")]
        sarif: Option<PathBuf>,

        /// Suppress the human-readable summary on stdout.
        #[arg(long)]
        quiet: bool,

        /// Exit code policy for CI gating (default: fail on high-severity
        /// findings). `never` always succeeds; `any-finding` also fails on
        /// medium/low risks and partial/unknown hardening.
        #[arg(long, value_enum, default_value_t = FailOn::High)]
        fail_on: FailOn,
    },

    /// Compare two firmware versions (directories or prior fw-harden JSON).
    Diff {
        /// Old firmware directory or previous scan JSON.
        old: PathBuf,

        /// New firmware directory or previous scan JSON.
        new: PathBuf,

        /// Write JSON diff here instead of stdout.
        #[arg(long, value_name = "FILE")]
        json: Option<PathBuf>,

        /// Also write a SARIF v2.1.0 diff report to this file.
        #[arg(long, value_name = "FILE")]
        sarif: Option<PathBuf>,

        /// Suppress the human-readable summary on stdout.
        #[arg(long)]
        quiet: bool,

        /// Exit code policy for CI gating (default: fail on high-severity
        /// findings such as hardening regressions).
        #[arg(long, value_enum, default_value_t = FailOn::High)]
        fail_on: FailOn,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut exit_code = 0i32;
    match cli.command {
        Command::Scan {
            paths,
            json,
            sarif: sarif_path,
            quiet,
            fail_on,
        } => {
            let outcome = analyzer::scan_roots(&paths);
            let report = &outcome.report;

            let json_bytes = serde_json::to_vec_pretty(report)?;
            write_output(json.as_deref(), &json_bytes)?;
            if let Some(p) = &sarif_path {
                let sarif_log = sarif::scan_to_sarif(report);
                write_output(Some(p), &serde_json::to_vec_pretty(&sarif_log)?)?;
            }
            if !quiet {
                print_scan(report);
            }
            if json.is_none() && sarif_path.is_none() {
                // Default: JSON on stdout for piping into CI tooling.
                let mut stdout = std::io::stdout().lock();
                stdout.write_all(&json_bytes)?;
                writeln!(stdout)?;
            }
            if scan_gate_triggered(report, fail_on) {
                exit_code = 2;
            }
        }
        Command::Diff {
            old,
            new,
            json,
            sarif: sarif_path,
            quiet,
            fail_on,
        } => {
            let (old_root, old_report) = diff::load_root(&old)?;
            let (new_root, new_report) = diff::load_root(&new)?;
            let diff_report = diff::diff_reports(&old_report, &new_report, &old_root, &new_root);

            let json_bytes = serde_json::to_vec_pretty(&diff_report)?;
            write_output(json.as_deref(), &json_bytes)?;
            if let Some(p) = &sarif_path {
                let sarif_log = sarif::diff_to_sarif(&diff_report);
                write_output(Some(p), &serde_json::to_vec_pretty(&sarif_log)?)?;
            }
            if !quiet {
                print_diff(&diff_report);
            }
            if json.is_none() && sarif_path.is_none() {
                let mut stdout = std::io::stdout().lock();
                stdout.write_all(&json_bytes)?;
                writeln!(stdout)?;
            }
            if diff_gate_triggered(&diff_report, fail_on) {
                exit_code = 2;
            }
        }
    }
    if exit_code != 0 {
        // Distinct from clap/anyhow's 1: 2 means "ran fine, policy failed".
        std::process::exit(exit_code);
    }
    Ok(())
}

/// Scan-side gating. High risk: any high-risk dangerous import or a
/// `disabled` hardening verdict. Any-finding: also medium/low risks and
/// partial/unknown verdicts. Parse errors always count as findings.
fn scan_gate_triggered(report: &fw_harden::model::ScanReport, policy: FailOn) -> bool {
    if policy == FailOn::Never {
        return false;
    }
    if !report.parse_errors.is_empty() {
        return true;
    }
    for bin in &report.binaries {
        for danger in &bin.dangerous_imports {
            match (danger.risk, policy) {
                (RiskLevel::High, _) => return true,
                (RiskLevel::Medium | RiskLevel::Low, FailOn::AnyFinding) => return true,
                _ => {}
            }
        }
        for check in &bin.hardening {
            match (check.verdict, policy) {
                (Verdict::Disabled, _) => return true,
                (Verdict::Partial | Verdict::Unknown, FailOn::AnyFinding) => return true,
                _ => {}
            }
        }
    }
    false
}

/// Diff-side gating. High risk: high-severity entries (hardening
/// regressions, new high-risk imports). Any-finding: every other entry.
fn diff_gate_triggered(diff: &fw_harden::model::DiffReport, policy: FailOn) -> bool {
    if policy == FailOn::Never {
        return false;
    }
    diff.entries
        .iter()
        .any(|e| e.severity == RiskLevel::High || policy == FailOn::AnyFinding)
}

fn write_output(path: Option<&Path>, bytes: &[u8]) -> Result<()> {
    match path {
        Some(p) => {
            if let Some(parent) = p.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent).with_context(|| {
                        format!("creating output directory {}", parent.display())
                    })?;
                }
            }
            std::fs::write(p, bytes).with_context(|| format!("writing {}", p.display()))?;
            eprintln!("wrote {}", p.display());
            Ok(())
        }
        None => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Human-readable rendering
// ---------------------------------------------------------------------------

fn verdict_label(v: Verdict) -> &'static str {
    match v {
        Verdict::Enabled => "[ENABLED ]",
        Verdict::Disabled => "[DISABLED]",
        Verdict::Partial => "[PARTIAL ]",
        Verdict::Unknown => "[UNKNOWN ]",
    }
}

fn risk_label(r: RiskLevel) -> &'static str {
    match r {
        RiskLevel::High => "HIGH",
        RiskLevel::Medium => "MED ",
        RiskLevel::Low => "LOW ",
    }
}

fn print_scan(report: &fw_harden::model::ScanReport) {
    eprintln!(
        "fw-harden {} — {} ELF binary(ies), {} non-ELF file(s) skipped, {} parse error(s)",
        report.tool_version,
        report.binaries.len(),
        report.skipped_non_elf,
        report.parse_errors.len()
    );
    for bin in &report.binaries {
        eprintln!("\n== {} ==", bin.path.display());
        eprintln!(
            "   {:?} {:?} {} | {} | sha256:{}",
            bin.identity.class,
            bin.identity.endianness,
            bin.identity.machine,
            bin.identity.elf_type,
            &bin.sha256[..16]
        );
        for check in &bin.hardening {
            eprintln!(
                "   {} {:14} {}",
                verdict_label(check.verdict),
                check.id,
                check.detail
            );
        }
        if !bin.needed_libraries.is_empty() {
            eprintln!("   NEEDED: {}", bin.needed_libraries.join(", "));
        }
        if let Some(soname) = &bin.soname {
            eprintln!("   SONAME: {soname}");
        }
        if !bin.fortified_calls.is_empty() {
            let names: Vec<&str> = bin
                .fortified_calls
                .iter()
                .map(|f| f.symbol.as_str())
                .collect();
            eprintln!("   FORTIFIED ({}): {}", names.len(), names.join(", "));
        }
        if !bin.dangerous_imports.is_empty() {
            eprintln!("   dangerous imports:");
            for d in &bin.dangerous_imports {
                eprintln!(
                    "     {} {:12} {}{}",
                    risk_label(d.risk),
                    d.symbol,
                    d.rationale,
                    if d.fortified {
                        " [fortified counterpart present]"
                    } else {
                        ""
                    }
                );
            }
        }
    }
    for err in &report.parse_errors {
        eprintln!("ERROR {}: {}", err.path.display(), err.message);
    }
}

fn print_diff(diff: &fw_harden::model::DiffReport) {
    eprintln!(
        "fw-harden diff: {} -> {}",
        diff.old_root.display(),
        diff.new_root.display()
    );
    eprintln!(
        "  {} finding(s): {} high, {} medium, {} low",
        diff.entries.len(),
        diff.summary.high_severity,
        diff.summary.medium_severity,
        diff.summary.low_severity
    );
    for entry in &diff.entries {
        eprintln!(
            "  {} {:?} {} — {}",
            risk_label(entry.severity),
            entry.kind,
            entry.path,
            entry.description
        );
    }
}
