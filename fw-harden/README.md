# fw-harden

Firmware ELF hardening & dangerous-import auditor for IoT firmware
acceptance testing. Point it at an extracted firmware tree (or individual
ELF files) and it reports the compile/link-time security posture of every
executable and shared library, compares two firmware versions for
regressions, and emits machine-readable reports for CI.

## What it checks

| Dimension | Signal used | Verdicts |
|---|---|---|
| **PIE / PIC** | `e_type` (`ET_DYN` vs `ET_EXEC`) | enabled / disabled / unknown (`.o`) |
| **NX** | `PT_GNU_STACK` flags, writable+executable `PT_LOAD` | enabled / disabled / unknown (legacy no-marker link) |
| **RELRO** | `PT_GNU_RELRO` + `DT_FLAGS DF_BIND_NOW` / `DT_FLAGS_1 DF_1_NOW` | enabled (full) / partial / disabled / unknown |
| **Stack canary** | undefined `__stack_chk_fail` / `__stack_chk_fail_local` in dynsym/symtab | enabled / disabled / unknown (stripped) |
| **FORTIFY_SOURCE** | imported `__*_chk` entry points (33 known fortified functions) | enabled / disabled / unknown |
| **Dangerous imports** | curated 40+ symbol database (high/medium/low, with rationale) | per-symbol finding |
| **Dynamic dependencies** | `DT_NEEDED`, `SONAME` | inventory + version diff |

Design notes that matter for real vendor binaries:

* **No libc or sysroot assumed.** All decisions come from loadable ELF
  metadata, so analysis works on stripped, statically linked and
  freestanding firmware. When evidence is genuinely unavailable (e.g.
  fully stripped static binaries), the answer is `unknown` — never a false
  `disabled`.
* **Toolchain quirks modeled.** lld on MIPS/PPC emits `BIND_NOW` without a
  `PT_GNU_RELRO` segment; that combination is reported as *partial* rather
  than mislabeled. PIE executables linked with `-z undefs` keep undefined
  symbols in `.symtab` rather than `.dynsym`; both tables are consulted.
* **Width and endianness:** ELF32/ELF64, little/big endian, covering
  x86, x86-64, ARM, AArch64, MIPS (all four width/endian variants),
  PowerPC, RISC-V and more via numeric `e_machine` fallback.

## Build

```sh
cargo build --release
# binary: target/release/fw-harden
```

## Usage

```sh
# Scan a firmware tree; JSON goes to stdout, human summary to stderr.
fw-harden scan ./firmware_root --sarif report.sarif --json report.json

# Scan multiple roots or individual files.
fw-harden scan bin/app usr/lib/*.so --json libs.json

# Compare two firmware versions. Inputs may be directories or previous
# fw-harden JSON reports (so a diff needs no access to the old firmware).
fw-harden diff firmware_v1 firmware_v2 --json diff.json --sarif diff.sarif
fw-harden diff old-scan.json new-scan.json --sarif diff.sarif
```

### CI exit codes (`--fail-on`)

| Policy | Behavior |
|---|---|
| `high` (default) | Exit **2** on high-risk dangerous imports, any `disabled` hardening verdict, high-severity diff entries (regressions), or parse errors |
| `any-finding` | Also fail on medium/low risks and partial/unknown states |
| `never` | Always exit 0 on successful execution; findings only appear in reports |

Exit code 1 still means a usage/runtime error; 2 means the policy fired.

## Outputs

* **JSON** — full structured report: SHA-256, ELF identity, per-dimension
  verdicts with evidence strings, `DT_NEEDED` list, dangerous imports with
  risk level and rationale, fortified-call inventory, all imported symbols.
* **SARIF v2.1.0** — validated against the official OASIS schema. Rule
  families `FW-HARD-*` (scan) and `FW-DIFF-*` (diff), with
  `error`/`warning`/`note` levels and `partialFingerprints` keyed by binary
  hash, ready for GitHub code scanning or any SARIF consumer.

### Version diff findings

`new-dangerous-import`, `removed-dangerous-import`,
`hardening-regression`, `new-dependency`, `new-binary`, `removed-binary`.
Binaries are matched by path relative to the scan root, so
`fw_v1/bin/app` and `fw_v2/bin/app` compare as the same artifact.
`unknown` verdicts never count as movement in either direction.

## Sample firmware

`samples/` contains freestanding C sources and a build script producing
two simulated firmware trees across **12 target triples** with
deliberately different hardening postures:

```sh
# requires: brew install llvm lld  (clang + lld + llvm-strip)
./samples/build.sh
```

Each tree contains, per architecture: a PIE executable (`gatewayd`), a
shared library (`libmgmt.so.1`), a stripped fully static binary
(`agentd`), plus a v2-only library (`libwatchdog`) and a v1-only utility
(`factory-tool`). The v2 build intentionally regresses gatewayd's
hardening flags and introduces a `popen()` call, exercising every diff
finding type.

## Testing

```sh
cargo test          # 24 tests: unit, hand-built-ELF integration, SARIF,
                    # and end-to-end tests against samples/build if present
```

The integration tests build parseable ELF32/64 big/little-endian fixtures
in pure Rust (no toolchain dependency). End-to-end tests self-skip when
the sample trees have not been built.

## Repository layout

```
src/
  analyzer.rs   ELF parsing + hardening/danger analysis and tree walking
  dangerdb.rs   curated dangerous-function and FORTIFY pair database
  diff.rs       version-to-version comparison
  sarif.rs      SARIF v2.1.0 serialization
  model.rs      serde data models
  main.rs       CLI (scan / diff, output routing, CI exit policy)
samples/        freestanding C sources + multi-arch build script
tests/          fixture builder + integration / SARIF / e2e tests
```
