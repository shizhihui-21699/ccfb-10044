//! Hand-rolled ELF fixture builder for integration tests.
//!
//! Produces parseable ELF32/ELF64, little/big-endian files with full
//! section + program headers, including a canonical .dynamic/.hash/.dynsym
//! layout so goblin derives the dynamic symbol count without any external
//! toolchain. No code in here runs; it only describes metadata.

use std::io::{Cursor, Write};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Elf32,
    Elf64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

/// An undefined symbol placed in both .dynsym and .symtab.
pub struct UndefSym {
    pub name: String,
}

pub struct Fixture {
    pub class: Class,
    pub endian: Endian,
    pub machine: u16,
    pub elf_type: u16,
    pub stack_exec: bool,
    pub relro_segment: bool,
    pub bind_now: bool,
    pub wx_load: bool,
    pub needed: Vec<String>,
    pub undef_syms: Vec<UndefSym>,
    /// When true, omit DT_HASH/DT_GNU_HASH and relocations so the dynamic
    /// loader cannot count symbols; models a fully stripped static binary.
    pub no_hash: bool,
}

impl Default for Fixture {
    fn default() -> Self {
        Self {
            class: Class::Elf64,
            endian: Endian::Little,
            machine: 62, // EM_X86_64
            elf_type: 3, // ET_DYN
            stack_exec: false,
            relro_segment: true,
            bind_now: true,
            wx_load: false,
            needed: vec!["libc.so.6".to_string()],
            undef_syms: Vec::new(),
            no_hash: false,
        }
    }
}

// section type / program header constants
const SHT_STRTAB: u32 = 3;
const SHT_HASH: u32 = 5;
const SHT_DYNAMIC: u32 = 6;
const SHT_DYNSYM: u32 = 11;
const SHT_SYMTAB: u32 = 2;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_GNU_RELRO: u32 = 0x6474_e552;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_STRSZ: i64 = 10;
const DT_FLAGS: i64 = 30;
const DT_FLAGS_1: i64 = 0x6fff_fffb;
const DF_BIND_NOW: u64 = 8;
const DF_1_NOW: u64 = 1;

struct Out {
    buf: Cursor<Vec<u8>>,
    endian: Endian,
}

impl Out {
    fn new(endian: Endian) -> Self {
        Self {
            buf: Cursor::new(Vec::new()),
            endian,
        }
    }
    fn u16(&mut self, v: u16) {
        let b = match self.endian {
            Endian::Little => v.to_le_bytes(),
            Endian::Big => v.to_be_bytes(),
        };
        self.buf.write_all(&b).unwrap();
    }
    fn u32(&mut self, v: u32) {
        let b = match self.endian {
            Endian::Little => v.to_le_bytes(),
            Endian::Big => v.to_be_bytes(),
        };
        self.buf.write_all(&b).unwrap();
    }
    fn u64(&mut self, v: u64) {
        let b = match self.endian {
            Endian::Little => v.to_le_bytes(),
            Endian::Big => v.to_be_bytes(),
        };
        self.buf.write_all(&b).unwrap();
    }
    fn bytes(&mut self, b: &[u8]) {
        self.buf.write_all(b).unwrap();
    }
    fn pos(&self) -> usize {
        self.buf.position() as usize
    }
    fn into_vec(self) -> Vec<u8> {
        self.buf.into_inner()
    }
}

fn align_up(v: usize, a: usize) -> usize {
    v.div_ceil(a) * a
}

/// Build a string table from names; returns (bytes, offset per name).
/// Index 0 is always the empty string.
fn build_strtab(names: &[String]) -> (Vec<u8>, Vec<usize>) {
    let mut data = vec![0u8];
    let mut offsets = Vec::with_capacity(names.len());
    for n in names {
        offsets.push(data.len());
        data.extend_from_slice(n.as_bytes());
        data.push(0);
    }
    (data, offsets)
}

impl Fixture {
    pub fn build(&self) -> Vec<u8> {
        let is64 = self.class == Class::Elf64;
        let ehdr_size = if is64 { 64 } else { 52 };
        let phdr_size = if is64 { 56 } else { 32 };
        let shdr_size = if is64 { 64 } else { 40 };
        let sym_size = if is64 { 24 } else { 16 };
        let dyn_size = if is64 { 16 } else { 8 };

        // ---- section names (.shstrtab) ----
        let sh_names = [
            "",
            ".shstrtab",
            ".dynstr",
            ".dynsym",
            ".hash",
            ".dynamic",
            ".strtab",
            ".symtab",
        ];
        let (shstrtab, sh_name_off) = build_strtab(&sh_names.map(String::from));

        // ---- dynamic strings: NEEDED libs + undefined symbol names ----
        let mut dynstr_names: Vec<String> = self.needed.clone();
        dynstr_names.extend(self.undef_syms.iter().map(|s| s.name.clone()));
        let (dynstr, dynstr_off) = build_strtab(&dynstr_names);
        let needed_offsets: Vec<usize> = self
            .needed
            .iter()
            .enumerate()
            .map(|(i, _)| dynstr_off[i])
            .collect();
        let sym_name_offsets: Vec<usize> = (0..self.undef_syms.len())
            .map(|i| dynstr_off[self.needed.len() + i])
            .collect();

        // ---- symbol tables: null symbol + undefined symbols ----
        let nsym = self.undef_syms.len() + 1;
        let dynsym = {
            let mut o = Out::new(self.endian);
            // null symbol
            if is64 {
                o.u32(0);
                o.bytes(&[0, 0]);
                o.u16(0);
                o.u64(0);
                o.u64(0);
            } else {
                o.u32(0);
                o.u32(0);
                o.u32(0);
                o.bytes(&[0, 0]);
                o.u16(0);
            }
            for name_off in &sym_name_offsets {
                if is64 {
                    o.u32(*name_off as u32); // st_name
                    o.bytes(&[0x10, 0]); // STB_GLOBAL | STT_NOTYPE, st_other
                    o.u16(0); // st_shndx = SHN_UNDEF
                    o.u64(0); // st_value
                    o.u64(0); // st_size
                } else {
                    o.u32(*name_off as u32);
                    o.u32(0);
                    o.u32(0);
                    o.bytes(&[0x10, 0]);
                    o.u16(0);
                }
            }
            o.into_vec()
        };
        assert_eq!(dynsym.len(), nsym * sym_size);

        // ---- hash table: nbucket=1, nchain=nsym ----
        let hash = {
            let mut o = Out::new(self.endian);
            o.u32(1);
            o.u32(nsym as u32);
            o.u32(0); // bucket[0]
            for _ in 0..nsym {
                o.u32(0); // chain
            }
            o.into_vec()
        };

        // ---- dynamic section (offsets patched later) ----
        // entries: NEEDED* (needed.len), HASH?, STRTAB, SYMTAB, STRSZ,
        //          FLAGS?, FLAGS_1?, NULL
        let mut ndyn = self.needed.len() + 4;
        if self.bind_now {
            ndyn += 2;
        }
        if !self.no_hash {
            ndyn += 1;
        }
        ndyn += 1;
        let dynamic_len = ndyn * dyn_size;

        // ---- static strtab/symtab mirror the dynamic ones ----
        let strtab = dynstr.clone();
        let symtab = dynsym.clone();

        // ---- section layout (vaddr == offset, one identity PT_LOAD) ----
        // section index: 0 null,1 shstrtab,2 dynstr,3 dynsym,4 hash,
        //                5 dynamic,6 strtab,7 symtab
        let mut off = ehdr_size;
        // program headers follow the ELF header
        let nph = if self.relro_segment { 4 } else { 3 };
        off += nph * phdr_size;
        off = align_up(off, 8);

        let mut sec_off = [0usize; 8];
        let mut sec_size = [0usize; 8];
        let bodies: [&[u8]; 8] = [
            &[],
            &shstrtab,
            &dynstr,
            &dynsym,
            &hash,
            &[], // dynamic, placeholder length
            &strtab,
            &symtab,
        ];
        for idx in 1..8 {
            sec_off[idx] = off;
            if idx == 5 {
                sec_size[idx] = dynamic_len;
                off += dynamic_len;
            } else {
                sec_size[idx] = bodies[idx].len();
                off += bodies[idx].len();
            }
            off = align_up(off, 8);
        }
        let shoff = off;
        let total_size = shoff + 8 * shdr_size;

        // ---- emit ELF header ----
        let mut out = Out::new(self.endian);
        out.bytes(&[0x7f, b'E', b'L', b'F']);
        out.bytes(&[if is64 { 2 } else { 1 }]); // EI_CLASS
        out.bytes(&[if self.endian == Endian::Little { 1 } else { 2 }]); // EI_DATA
        out.bytes(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // EI_VERSION + padding
        if is64 {
            out.u16(self.elf_type);
            out.u16(self.machine);
            out.u32(1); // e_version
            out.u64(0); // e_entry
            out.u64(ehdr_size as u64); // e_phoff
            out.u64(shoff as u64); // e_shoff
            out.u32(0); // e_flags
            out.u16(ehdr_size as u16);
            out.u16(phdr_size as u16);
            out.u16(nph as u16);
            out.u16(shdr_size as u16);
            out.u16(8);
            out.u16(1); // e_shstrndx
        } else {
            out.u16(self.elf_type);
            out.u16(self.machine);
            out.u32(1);
            out.u32(0); // e_entry
            out.u32(ehdr_size as u32); // e_phoff
            out.u32(shoff as u32); // e_shoff
            out.u32(0);
            out.u16(ehdr_size as u16);
            out.u16(phdr_size as u16);
            out.u16(nph as u16);
            out.u16(shdr_size as u16);
            out.u16(8);
            out.u16(1);
        }

        // ---- program headers ----
        let load_flags = if self.wx_load {
            PF_R | PF_W | PF_X
        } else {
            PF_R | PF_W
        };
        self.emit_phdr(
            &mut out,
            PT_LOAD,
            load_flags,
            0,
            0,
            total_size as u64,
            total_size as u64,
        );
        self.emit_phdr(
            &mut out,
            PT_DYNAMIC,
            PF_R | PF_W,
            sec_off[5] as u64,
            sec_off[5] as u64,
            dynamic_len as u64,
            dynamic_len as u64,
        );
        let stack_flags = PF_R | PF_W | if self.stack_exec { PF_X } else { 0 };
        self.emit_phdr(&mut out, PT_GNU_STACK, stack_flags, 0, 0, 0, 0);
        if self.relro_segment {
            self.emit_phdr(
                &mut out,
                PT_GNU_RELRO,
                PF_R,
                sec_off[5] as u64,
                sec_off[5] as u64,
                dynamic_len as u64,
                dynamic_len as u64,
            );
        }

        // ---- section bodies ----
        // pad to first section offset
        while out.pos() < sec_off[1] {
            out.bytes(&[0]);
        }
        for idx in 1..8 {
            while out.pos() < sec_off[idx] {
                out.bytes(&[0]);
            }
            if idx == 5 {
                self.emit_dynamic(
                    &mut out,
                    &needed_offsets,
                    sec_off[4] as u64,
                    sec_off[2] as u64,
                    sec_off[3] as u64,
                    dynstr.len() as u64,
                );
            } else {
                out.bytes(bodies[idx]);
            }
        }
        while out.pos() < shoff {
            out.bytes(&[0]);
        }

        // ---- section headers ----
        let sh_types = [
            0u32,
            SHT_STRTAB,
            SHT_STRTAB,
            SHT_DYNSYM,
            SHT_HASH,
            SHT_DYNAMIC,
            SHT_STRTAB,
            SHT_SYMTAB,
        ];
        let sh_links = [0u32, 0, 0, 2, 3, 2, 0, 6];
        let sh_entsize = [
            0u64,
            0,
            0,
            sym_size as u64,
            4,
            dyn_size as u64,
            0,
            sym_size as u64,
        ];
        for idx in 0..8 {
            if is64 {
                out.u32(sh_name_off[idx] as u32);
                out.u32(sh_types[idx]);
                out.u64(0); // sh_flags
                out.u64(sec_off[idx] as u64); // sh_addr (identity mapped)
                out.u64(sec_off[idx] as u64); // sh_offset
                out.u64(sec_size[idx] as u64);
                out.u32(sh_links[idx]);
                out.u32(0);
                out.u64(8);
                out.u64(sh_entsize[idx]);
            } else {
                out.u32(sh_name_off[idx] as u32);
                out.u32(sh_types[idx]);
                out.u32(0);
                out.u32(sec_off[idx] as u32);
                out.u32(sec_off[idx] as u32);
                out.u32(sec_size[idx] as u32);
                out.u32(sh_links[idx]);
                out.u32(0);
                out.u32(4);
                out.u32(sh_entsize[idx] as u32);
            }
        }

        let data = out.into_vec();
        assert_eq!(data.len(), total_size);
        data
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_phdr(
        &self,
        out: &mut Out,
        p_type: u32,
        flags: u32,
        offset: u64,
        vaddr: u64,
        filesz: u64,
        memsz: u64,
    ) {
        let is64 = self.class == Class::Elf64;
        if is64 {
            out.u32(p_type);
            out.u32(flags);
            out.u64(offset);
            out.u64(vaddr);
            out.u64(vaddr); // p_paddr
            out.u64(filesz);
            out.u64(memsz);
            out.u64(0x1000); // p_align
        } else {
            out.u32(p_type);
            out.u32(offset as u32);
            out.u32(vaddr as u32);
            out.u32(vaddr as u32);
            out.u32(filesz as u32);
            out.u32(memsz as u32);
            out.u32(flags);
            out.u32(0x1000);
        }
    }

    fn emit_dynamic(
        &self,
        out: &mut Out,
        needed_offsets: &[usize],
        hash_addr: u64,
        strtab_addr: u64,
        symtab_addr: u64,
        strsz: u64,
    ) {
        let is64 = self.class == Class::Elf64;
        let entry = |out: &mut Out, tag: i64, val: u64| {
            if is64 {
                out.u64(tag as u64);
                out.u64(val);
            } else {
                out.u32(tag as u32);
                out.u32(val as u32);
            }
        };
        for noff in needed_offsets {
            entry(out, DT_NEEDED, *noff as u64);
        }
        if !self.no_hash {
            entry(out, DT_HASH, hash_addr);
        }
        entry(out, DT_STRTAB, strtab_addr);
        entry(out, DT_SYMTAB, symtab_addr);
        entry(out, DT_STRSZ, strsz);
        if self.bind_now {
            entry(out, DT_FLAGS, DF_BIND_NOW);
            entry(out, DT_FLAGS_1, DF_1_NOW);
        }
        entry(out, DT_NULL, 0);
    }
}
