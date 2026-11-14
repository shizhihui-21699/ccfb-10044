//! fw-harden: firmware ELF hardening and dangerous-import auditor.

pub mod analyzer;
pub mod dangerdb;
pub mod diff;
pub mod model;
pub mod sarif;

/// Re-exported timestamp helper so other modules do not depend on chrono
/// directly.
pub fn now_rfc3339_public() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
