//! Curated database of libc functions that are historically associated with
//! memory-safety or command-injection weaknesses in firmware code.
//!
//! The list is intentionally conservative and each entry carries a short
//! rationale so SARIF consumers can triage findings.

use crate::model::RiskLevel;

pub struct DangerEntry {
    pub name: &'static str,
    pub risk: RiskLevel,
    pub rationale: &'static str,
}

/// Returned by [`lookup`].
pub fn lookup(symbol: &str) -> Option<&'static DangerEntry> {
    DATABASE.iter().find(|e| e.name == symbol)
}

pub fn database() -> &'static [DangerEntry] {
    DATABASE
}

/// Map a fortified symbol (`__foo_chk`) to its ordinary counterpart (`foo`).
pub fn fortified_counterpart(chk_symbol: &str) -> Option<&'static str> {
    FORTIFY_PAIRS
        .iter()
        .find(|(chk, _)| *chk == chk_symbol)
        .map(|(_, base)| *base)
}

/// All known `__*_chk` names, used both for FORTIFY detection and for
/// avoiding false dangerous-import hits.
pub fn is_fortified_symbol(symbol: &str) -> bool {
    FORTIFY_PAIRS.iter().any(|(chk, _)| *chk == symbol)
}

static DATABASE: &[DangerEntry] = &[
    // ---- High: unbounded / easily misused memory and string operations ----
    DangerEntry {
        name: "gets",
        risk: RiskLevel::High,
        rationale: "No bounds argument; removed from C11. Any use is a stack buffer overflow waiting to happen.",
    },
    DangerEntry {
        name: "strcpy",
        risk: RiskLevel::High,
        rationale: "Unbounded string copy; destination overflow when source is attacker controlled.",
    },
    DangerEntry {
        name: "strcat",
        risk: RiskLevel::High,
        rationale: "Unbounded string concatenation; overflow when combined length exceeds destination.",
    },
    DangerEntry {
        name: "sprintf",
        risk: RiskLevel::High,
        rationale: "Unbounded formatted write; classic stack overflow vector. Prefer snprintf.",
    },
    DangerEntry {
        name: "vsprintf",
        risk: RiskLevel::High,
        rationale: "va_list variant of sprintf with the same unbounded-write risk.",
    },
    DangerEntry {
        name: "scanf",
        risk: RiskLevel::High,
        rationale: "%s/%[ conversions without width specifiers overflow fixed buffers.",
    },
    DangerEntry {
        name: "sscanf",
        risk: RiskLevel::High,
        rationale: "Same unbounded %s conversion risk as scanf.",
    },
    DangerEntry {
        name: "fscanf",
        risk: RiskLevel::High,
        rationale: "Same unbounded %s conversion risk as scanf.",
    },
    DangerEntry {
        name: "alloca",
        risk: RiskLevel::High,
        rationale: "Stack allocation sized by input can exhaust/overflow the stack; no recoverable failure.",
    },
    DangerEntry {
        name: "realpath",
        risk: RiskLevel::High,
        rationale: "Legacy form with NULL second argument uses PATH_MAX-sized caller assumptions; use the 2-arg POSIX form.",
    },
    DangerEntry {
        name: "getwd",
        risk: RiskLevel::High,
        rationale: "Removed from POSIX; fixed-size buffer cannot represent long paths safely.",
    },
    // ---- High: command execution and dynamic loader ----
    DangerEntry {
        name: "system",
        risk: RiskLevel::High,
        rationale: "Spawns /bin/sh on a string; shell metacharacter injection if any input is interpolated.",
    },
    DangerEntry {
        name: "popen",
        risk: RiskLevel::High,
        rationale: "Shell-backed pipe; same command-injection exposure as system().",
    },
    DangerEntry {
        name: "execl",
        risk: RiskLevel::High,
        rationale: "NULL-terminated varargs exec; accidental NULL termination and PATH handling bugs are common.",
    },
    DangerEntry {
        name: "execlp",
        risk: RiskLevel::High,
        rationale: "PATH-searching exec; vulnerable to PATH hijacking in firmware environments.",
    },
    DangerEntry {
        name: "execvp",
        risk: RiskLevel::High,
        rationale: "PATH-searching exec; PATH hijacking and argv termination risks.",
    },
    DangerEntry {
        name: "execvpe",
        risk: RiskLevel::High,
        rationale: "PATH-searching exec with explicit environment; PATH/env hijacking risks.",
    },
    DangerEntry {
        name: "dlopen",
        risk: RiskLevel::High,
        rationale: "Loads shared objects at runtime; attacker-controlled paths enable library injection.",
    },
    DangerEntry {
        name: "dlsym",
        risk: RiskLevel::High,
        rationale: "Resolves symbols dynamically; combined with dlopen it enables runtime code-loading attacks.",
    },
    // ---- Medium: bounded but misuse-prone ----
    DangerEntry {
        name: "strncpy",
        risk: RiskLevel::Medium,
        rationale: "Does not guarantee NUL termination; truncation bugs frequently become overflows later.",
    },
    DangerEntry {
        name: "strncat",
        risk: RiskLevel::Medium,
        rationale: "Size argument is remaining space, not total size; classic off-by-N overflow source.",
    },
    DangerEntry {
        name: "snprintf",
        risk: RiskLevel::Medium,
        rationale: "Generally safe, but return value (would-be length) is often mishandled and truncation is silent.",
    },
    DangerEntry {
        name: "memcpy",
        risk: RiskLevel::Medium,
        rationale: "Safe when length is proven; in practice a leading cause of buffer overflows when length is attacker influenced.",
    },
    DangerEntry {
        name: "memmove",
        risk: RiskLevel::Medium,
        rationale: "Same length-validation exposure as memcpy despite correct overlap handling.",
    },
    DangerEntry {
        name: "memset",
        risk: RiskLevel::Low,
        rationale: "Rarely dangerous itself; flagged because compiler elision can remove security-sensitive clearing.",
    },
    DangerEntry {
        name: "strlen",
        risk: RiskLevel::Low,
        rationale: "Reads until NUL; crashes on unterminated attacker buffers. Risk is mostly availability.",
    },
    DangerEntry {
        name: "strtok",
        risk: RiskLevel::Medium,
        rationale: "Global hidden state and in-place mutation; not reentrant and confuses parser security logic.",
    },
    DangerEntry {
        name: "strtok_r",
        risk: RiskLevel::Low,
        rationale: "Reentrant variant; still mutates input and is easy to misparse.",
    },
    DangerEntry {
        name: "getenv",
        risk: RiskLevel::Medium,
        rationale: "Environment-controlled configuration; tainted values frequently flow into paths/commands.",
    },
    DangerEntry {
        name: "tmpnam",
        risk: RiskLevel::Medium,
        rationale: "Predictable temporary file name; TOCTOU and symlink attacks. Use mkstemp.",
    },
    DangerEntry {
        name: "tempnam",
        risk: RiskLevel::Medium,
        rationale: "Same predictable-name TOCTOU class as tmpnam.",
    },
    DangerEntry {
        name: "mktemp",
        risk: RiskLevel::Medium,
        rationale: "Legacy template form is racy; mkstemp/mkdtemp are the safe replacements.",
    },
    DangerEntry {
        name: "rand",
        risk: RiskLevel::Medium,
        rationale: "Non-cryptographic PRNG; unsafe for tokens, keys or any security decision.",
    },
    DangerEntry {
        name: "random",
        risk: RiskLevel::Medium,
        rationale: "Still non-cryptographic despite the name; do not use for security tokens.",
    },
    DangerEntry {
        name: "atoi",
        risk: RiskLevel::Low,
        rationale: "Undefined behavior on out-of-range input; prefer strtol with errno checks.",
    },
    DangerEntry {
        name: "atol",
        risk: RiskLevel::Low,
        rationale: "Undefined behavior on out-of-range input; prefer strtol.",
    },
    DangerEntry {
        name: "atoll",
        risk: RiskLevel::Low,
        rationale: "Undefined behavior on out-of-range input; prefer strtoll.",
    },
    DangerEntry {
        name: "chmod",
        risk: RiskLevel::Medium,
        rationale: "Mode changes on attacker-influenced paths can weaken file permissions.",
    },
    DangerEntry {
        name: "chown",
        risk: RiskLevel::Medium,
        rationale: "Ownership changes on attacker-influenced paths enable privilege handoff.",
    },
    DangerEntry {
        name: "mount",
        risk: RiskLevel::Medium,
        rationale: "Namespace/filesystem manipulation; dangerous when flags or sources are tainted.",
    },
    DangerEntry {
        name: "ioctl",
        risk: RiskLevel::Medium,
        rationale: "Device-specific ABI surface; firmware bugs here often become local root primitives.",
    },
];

/// (`__*_chk` fortified name, ordinary counterpart).
static FORTIFY_PAIRS: &[(&str, &str)] = &[
    ("__sprintf_chk", "sprintf"),
    ("__vsprintf_chk", "vsprintf"),
    ("__snprintf_chk", "snprintf"),
    ("__vsnprintf_chk", "vsnprintf"),
    ("__printf_chk", "printf"),
    ("__vprintf_chk", "vprintf"),
    ("__fprintf_chk", "fprintf"),
    ("__vfprintf_chk", "vfprintf"),
    ("__memcpy_chk", "memcpy"),
    ("__memmove_chk", "memmove"),
    ("__memset_chk", "memset"),
    ("__strcpy_chk", "strcpy"),
    ("__strncpy_chk", "strncpy"),
    ("__strcat_chk", "strcat"),
    ("__strncat_chk", "strncat"),
    ("__stpcpy_chk", "stpcpy"),
    ("__stpncpy_chk", "stpncpy"),
    ("__read_chk", "read"),
    ("__readlink_chk", "readlink"),
    ("__readlinkat_chk", "readlinkat"),
    ("__recv_chk", "recv"),
    ("__recvfrom_chk", "recvfrom"),
    ("__fgets_chk", "fgets"),
    ("__fgets_unlocked_chk", "fgets_unlocked"),
    ("__gethostname_chk", "gethostname"),
    ("__getdomainname_chk", "getdomainname"),
    ("__longjmp_chk", "longjmp"),
    ("__wcscpy_chk", "wcscpy"),
    ("__wcsncpy_chk", "wcsncpy"),
    ("__wcscat_chk", "wcscat"),
    ("__wcsncat_chk", "wcsncat"),
    ("__fread_chk", "fread"),
    ("__fread_unlocked_chk", "fread_unlocked"),
    ("__wcsnlen_chk", "wcsnlen"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::RiskLevel;

    #[test]
    fn known_dangerous_functions_are_classified() {
        assert_eq!(lookup("gets").unwrap().risk, RiskLevel::High);
        assert_eq!(lookup("strncpy").unwrap().risk, RiskLevel::Medium);
        assert!(lookup("memset").is_some());
        // Unrelated symbols must never match.
        assert!(lookup("printf").is_none());
        assert!(lookup("not_a_real_function").is_none());
    }

    #[test]
    fn fortify_pairs_resolve_both_directions() {
        assert!(is_fortified_symbol("__memcpy_chk"));
        assert!(!is_fortified_symbol("memcpy"));
        assert_eq!(fortified_counterpart("__strcpy_chk"), Some("strcpy"));
        assert_eq!(fortified_counterpart("__sprintf_chk"), Some("sprintf"));
        assert_eq!(fortified_counterpart("memcpy"), None);
    }
}
