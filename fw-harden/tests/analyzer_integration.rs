//! Integration tests driving the public analyzer against hand-built ELF
//! fixtures, covering ELF32/64 and both endiannesses without any external
//! toolchain dependency.

mod common;

use common::{Class, Endian, Fixture, UndefSym};
use fw_harden::analyzer::{analyze_file, is_elf, scan_roots};
use fw_harden::model::{ElfClass, Endianness, RiskLevel, Verdict};
use std::path::PathBuf;
use std::sync::Mutex;

// Keep TempDir handles alive for the whole process; tempfile cleans up on
// drop, which would otherwise delete the fixture files between write and
// analyze. Leaked once, reclaimed by the OS with the rest of /tmp.
static TEMP_ROOTS: Mutex<Vec<tempfile::TempDir>> = Mutex::new(Vec::new());

fn write_temp(bytes: &[u8], name: &str) -> PathBuf {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).expect("write fixture");
    TEMP_ROOTS.lock().unwrap().push(dir);
    path
}

fn verdict_of(report: &fw_harden::model::BinaryReport, id: &str) -> Verdict {
    report.check(id).unwrap().verdict
}

#[test]
fn fully_hardened_elf64_little_endian() {
    let fixture = Fixture {
        undef_syms: vec![
            UndefSym {
                name: "gets".into(),
            },
            UndefSym {
                name: "__memcpy_chk".into(),
            },
            UndefSym {
                name: "__stack_chk_fail".into(),
            },
        ],
        ..Default::default()
    };
    let path = write_temp(&fixture.build(), "hardened.so");
    let report = analyze_file(&path).unwrap().expect("ELF recognized");

    assert_eq!(report.identity.class, ElfClass::Elf64);
    assert_eq!(report.identity.endianness, Endianness::Little);
    assert_eq!(verdict_of(&report, "pie"), Verdict::Enabled);
    assert_eq!(verdict_of(&report, "nx"), Verdict::Enabled);
    assert_eq!(verdict_of(&report, "relro"), Verdict::Enabled);
    assert_eq!(verdict_of(&report, "stack-canary"), Verdict::Enabled);
    assert_eq!(verdict_of(&report, "fortify"), Verdict::Enabled);

    assert!(report.needed_libraries.contains(&"libc.so.6".to_string()));
    let gets = report
        .dangerous_imports
        .iter()
        .find(|d| d.symbol == "gets")
        .expect("gets flagged");
    assert_eq!(gets.risk, RiskLevel::High);
    assert!(report
        .fortified_calls
        .iter()
        .any(|f| f.symbol == "__memcpy_chk"));
    assert!(report
        .imported_symbols
        .contains(&"__stack_chk_fail".to_string()));
    assert_eq!(report.sha256.len(), 64);
}

#[test]
fn weak_elf32_big_endian_executable() {
    let fixture = Fixture {
        class: Class::Elf32,
        endian: Endian::Big,
        machine: 8,  // EM_MIPS
        elf_type: 2, // ET_EXEC
        stack_exec: true,
        relro_segment: false,
        bind_now: false,
        wx_load: false,
        undef_syms: vec![UndefSym {
            name: "strcpy".into(),
        }],
        ..Default::default()
    };
    let path = write_temp(&fixture.build(), "weak-mips");
    let report = analyze_file(&path).unwrap().expect("ELF recognized");

    assert_eq!(report.identity.class, ElfClass::Elf32);
    assert_eq!(report.identity.endianness, Endianness::Big);
    assert!(report.identity.machine.contains("MIPS"));
    assert_eq!(verdict_of(&report, "pie"), Verdict::Disabled);
    assert_eq!(verdict_of(&report, "nx"), Verdict::Disabled);
    assert_eq!(verdict_of(&report, "relro"), Verdict::Disabled);
    assert_eq!(verdict_of(&report, "stack-canary"), Verdict::Disabled);
    assert_eq!(verdict_of(&report, "fortify"), Verdict::Disabled);

    assert!(report
        .dangerous_imports
        .iter()
        .any(|d| d.symbol == "strcpy" && d.risk == RiskLevel::High));
}

#[test]
fn bind_now_without_relro_segment_is_partial() {
    // Mirrors lld's MIPS/PPC output: BIND_NOW present, no PT_GNU_RELRO.
    let fixture = Fixture {
        class: Class::Elf32,
        endian: Endian::Big,
        relro_segment: false,
        bind_now: true,
        ..Default::default()
    };
    let path = write_temp(&fixture.build(), "partial.so");
    let report = analyze_file(&path).unwrap().unwrap();
    assert_eq!(verdict_of(&report, "relro"), Verdict::Partial);
}

#[test]
fn relro_without_bind_now_is_partial() {
    let fixture = Fixture {
        relro_segment: true,
        bind_now: false,
        ..Default::default()
    };
    let path = write_temp(&fixture.build(), "lazy.so");
    let report = analyze_file(&path).unwrap().unwrap();
    assert_eq!(verdict_of(&report, "relro"), Verdict::Partial);
}

#[test]
fn writable_executable_load_segment_violates_nx() {
    let fixture = Fixture {
        stack_exec: false,
        wx_load: true,
        ..Default::default()
    };
    let path = write_temp(&fixture.build(), "wx.so");
    let report = analyze_file(&path).unwrap().unwrap();
    assert_eq!(verdict_of(&report, "nx"), Verdict::Disabled);
    assert!(report
        .check("nx")
        .unwrap()
        .detail
        .contains("writable and executable"));
}

#[test]
fn missing_gnu_stack_leaves_nx_unknown() {
    // Build a fixture then surgically remove the PT_GNU_STACK header by
    // rebuilding with a custom variant flag: emulate by zeroing the type
    // field of the third program header (index 2).
    let bytes = Fixture::default().build();
    let mut damaged = bytes.clone();
    let is64 = true;
    let phoff: usize = if is64 { 64 } else { 52 };
    let phdr_size: usize = if is64 { 56 } else { 32 };
    let gnu_stack = phoff + 2 * phdr_size;
    damaged[gnu_stack..gnu_stack + 4].copy_from_slice(&0u32.to_le_bytes()); // PT_NULL

    let path = write_temp(&damaged, "no-stack-hdr.so");
    let report = analyze_file(&path).unwrap().unwrap();
    assert_eq!(verdict_of(&report, "nx"), Verdict::Unknown);
}

#[test]
fn no_symbol_tables_degrades_canary_and_fortify_to_unknown() {
    // Strip dynamic symbol discovery (no DT_HASH -> zero dynsym count) and
    // remove section headers (zero e_shoff -> no SHT_SYMTAB either).
    let fixture = Fixture {
        undef_syms: vec![],
        no_hash: true,
        ..Default::default()
    };
    let mut bytes = fixture.build();
    let shoff = 0x28; // e_shoff for ELF64 LE
    bytes[shoff..shoff + 8].copy_from_slice(&0u64.to_le_bytes());
    let path = write_temp(&bytes, "stripped.so");
    let report = analyze_file(&path).unwrap().unwrap();
    assert_eq!(verdict_of(&report, "stack-canary"), Verdict::Unknown);
    assert_eq!(verdict_of(&report, "fortify"), Verdict::Unknown);
}

#[test]
fn non_elf_and_truncated_files_are_handled() {
    let dir = tempfile::tempdir().unwrap();
    let txt = dir.path().join("notes.txt");
    std::fs::write(&txt, b"just text").unwrap();
    assert!(!is_elf(&std::fs::read(&txt).unwrap()));
    assert!(analyze_file(&txt).unwrap().is_none());

    let truncated = dir.path().join("broken.elf");
    std::fs::write(&truncated, [0x7f, b'E', b'L', b'F', 2, 1, 1]).unwrap();
    assert!(analyze_file(&truncated).is_err());
}

#[test]
fn directory_scan_skips_non_elf_and_records_errors() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("readme"), b"hello").unwrap();
    let good = Fixture::default().build();
    std::fs::write(dir.path().join("a.so"), good).unwrap();
    std::fs::write(
        dir.path().join("bad.elf"),
        [0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0],
    )
    .unwrap();

    let outcome = scan_roots(&[dir.path().to_path_buf()]);
    assert_eq!(outcome.report.binaries.len(), 1);
    assert_eq!(outcome.report.skipped_non_elf, 1);
    assert_eq!(outcome.report.parse_errors.len(), 1);
}

#[test]
fn all_four_class_endian_combinations_parse() {
    for class in [Class::Elf32, Class::Elf64] {
        for endian in [Endian::Little, Endian::Big] {
            let fixture = Fixture {
                class,
                endian,
                machine: if endian == Endian::Big { 8 } else { 62 },
                ..Default::default()
            };
            let path = write_temp(&fixture.build(), "combo");
            let report = analyze_file(&path).unwrap().unwrap();
            assert_eq!(
                report.identity.class,
                if class == Class::Elf64 {
                    ElfClass::Elf64
                } else {
                    ElfClass::Elf32
                }
            );
            assert_eq!(
                report.identity.endianness,
                if endian == Endian::Little {
                    Endianness::Little
                } else {
                    Endianness::Big
                }
            );
        }
    }
}
