use anyhow::Result;
use capstone::prelude::*;
use goblin::Object;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Insn {
    pub addr: u64,
    pub bytes: String,
    pub mnemonic: String,
    pub op_str: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DisasmSection {
    pub section_name: String,
    pub base_addr: u64,
    pub instructions: Vec<Insn>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FullDisasm {
    pub arch: String,
    pub is_64: bool,
    pub sections: Vec<DisasmSection>,
    /// Total instruction count across all sections
    pub total_insns: usize,
    /// Call targets found (addr → count of callers)
    pub call_targets: HashMap<u64, usize>,
    /// Unique mnemonics and their frequency
    pub mnemonic_freq: HashMap<String, usize>,
}

/// Build a Capstone disassembler for the given arch string and bitness.
fn build_cs(arch: &str, is_64: bool) -> Result<Capstone> {
    let cs = match arch {
        "x86_64" | "x86" | "i386" => {
            if is_64 {
                Capstone::new()
                    .x86()
                    .mode(arch::x86::ArchMode::Mode64)
                    .syntax(arch::x86::ArchSyntax::Intel)
                    .detail(false)
                    .build()
            } else {
                Capstone::new()
                    .x86()
                    .mode(arch::x86::ArchMode::Mode32)
                    .syntax(arch::x86::ArchSyntax::Intel)
                    .detail(false)
                    .build()
            }
        }
        "aarch64" => Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(false)
            .build(),
        "arm" => Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Arm)
            .detail(false)
            .build(),
        _ => {
            // Default to x86-64 for unknown archs
            Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(false)
                .build()
        }
    }
    .map_err(|e| anyhow::anyhow!("capstone init: {:?}", e))?;
    Ok(cs)
}

/// Disassemble a fixed number of instructions from a code buffer.
/// Used by the existing `disasm` subcommand (entry point only).
pub fn disassemble(code: &[u8], base_addr: u64, is_64: bool, count: usize) -> Result<Vec<Insn>> {
    let cs = build_cs(if is_64 { "x86_64" } else { "x86" }, is_64)?;
    let insns = cs
        .disasm_count(code, base_addr, count)
        .map_err(|e| anyhow::anyhow!("disasm: {:?}", e))?;

    Ok(insns
        .iter()
        .map(|i| Insn {
            addr: i.address(),
            bytes: i
                .bytes()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" "),
            mnemonic: i.mnemonic().unwrap_or("").to_string(),
            op_str: i.op_str().unwrap_or("").to_string(),
        })
        .collect())
}

/// Disassemble all executable sections of a PE or ELF binary.
///
/// For each executable section:
/// - Disassembles all instructions (capped at `max_insns_per_section` to
///   prevent runaway on huge binaries; pass `usize::MAX` for no cap)
/// - Collects call targets (direct CALL instruction operands)
/// - Builds a mnemonic frequency table across all sections
///
/// Returns a `FullDisasm` summary suitable for JSON output or further
/// analysis.
pub fn disassemble_full(data: &[u8], max_insns_per_section: usize) -> Result<FullDisasm> {
    match Object::parse(data)? {
        Object::PE(pe) => {
            let arch = if pe.is_64 { "x86_64" } else { "x86" };
            let cs = build_cs(arch, pe.is_64)?;
            let mut sections_out = Vec::new();
            let mut call_targets: HashMap<u64, usize> = HashMap::new();
            let mut mnemonic_freq: HashMap<String, usize> = HashMap::new();
            let mut total = 0usize;

            for sec in &pe.sections {
                let chars = sec.characteristics;
                // IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE
                if chars & 0x2000_0020 == 0 {
                    continue;
                }
                let off = sec.pointer_to_raw_data as usize;
                let sz = sec.size_of_raw_data as usize;
                let code = match data.get(off..off + sz) {
                    Some(s) => s,
                    None => continue,
                };
                let va = pe.image_base as u64 + sec.virtual_address as u64;
                let sec_name = String::from_utf8_lossy(&sec.name)
                    .trim_matches('\0')
                    .to_string();

                let insns_raw = cs
                    .disasm_all(code, va)
                    .map_err(|e| anyhow::anyhow!("disasm {}: {:?}", sec_name, e))?;

                let mut insns = Vec::new();
                for i in insns_raw.iter().take(max_insns_per_section) {
                    let mn = i.mnemonic().unwrap_or("").to_string();
                    let op = i.op_str().unwrap_or("").to_string();

                    // Track call targets for xref building
                    if mn == "call" {
                        if let Ok(target) = u64::from_str_radix(op.trim_start_matches("0x"), 16) {
                            *call_targets.entry(target).or_insert(0) += 1;
                        }
                    }
                    *mnemonic_freq.entry(mn.clone()).or_insert(0) += 1;

                    insns.push(Insn {
                        addr: i.address(),
                        bytes: i
                            .bytes()
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(" "),
                        mnemonic: mn,
                        op_str: op,
                    });
                }
                total += insns.len();
                sections_out.push(DisasmSection {
                    section_name: sec_name,
                    base_addr: va,
                    instructions: insns,
                });
            }

            Ok(FullDisasm {
                arch: arch.to_string(),
                is_64: pe.is_64,
                sections: sections_out,
                total_insns: total,
                call_targets,
                mnemonic_freq,
            })
        }

        Object::Elf(elf) => {
            let arch = match elf.header.e_machine {
                goblin::elf::header::EM_X86_64 => "x86_64",
                goblin::elf::header::EM_386 => "x86",
                goblin::elf::header::EM_AARCH64 => "aarch64",
                goblin::elf::header::EM_ARM => "arm",
                _ => "x86_64",
            };
            let cs = build_cs(arch, elf.is_64)?;
            let mut sections_out = Vec::new();
            let mut call_targets: HashMap<u64, usize> = HashMap::new();
            let mut mnemonic_freq: HashMap<String, usize> = HashMap::new();
            let mut total = 0usize;

            for sh in &elf.section_headers {
                // SHF_EXECINSTR = 0x4
                if sh.sh_flags & 0x4 == 0 || sh.sh_size == 0 {
                    continue;
                }
                let off = sh.sh_offset as usize;
                let sz = sh.sh_size as usize;
                let code = match data.get(off..off + sz) {
                    Some(s) => s,
                    None => continue,
                };
                let va = sh.sh_addr;
                let sec_name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();

                let insns_raw = cs
                    .disasm_all(code, va)
                    .map_err(|e| anyhow::anyhow!("disasm {}: {:?}", sec_name, e))?;

                let mut insns = Vec::new();
                for i in insns_raw.iter().take(max_insns_per_section) {
                    let mn = i.mnemonic().unwrap_or("").to_string();
                    let op = i.op_str().unwrap_or("").to_string();

                    if mn == "call" || mn == "bl" || mn == "blx" {
                        if let Ok(target) = u64::from_str_radix(op.trim_start_matches("0x"), 16) {
                            *call_targets.entry(target).or_insert(0) += 1;
                        }
                    }
                    *mnemonic_freq.entry(mn.clone()).or_insert(0) += 1;

                    insns.push(Insn {
                        addr: i.address(),
                        bytes: i
                            .bytes()
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(" "),
                        mnemonic: mn,
                        op_str: op,
                    });
                }
                total += insns.len();
                sections_out.push(DisasmSection {
                    section_name: sec_name,
                    base_addr: va,
                    instructions: insns,
                });
            }

            Ok(FullDisasm {
                arch: arch.to_string(),
                is_64: elf.is_64,
                sections: sections_out,
                total_insns: total,
                call_targets,
                mnemonic_freq,
            })
        }

        _ => anyhow::bail!("unsupported format for full disassembly"),
    }
}
