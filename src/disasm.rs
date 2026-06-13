use anyhow::Result;
use capstone::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Insn {
    pub addr: u64,
    pub bytes: String,
    pub mnemonic: String,
    pub op_str: String,
}

pub fn disassemble(code: &[u8], base_addr: u64, is_64: bool, count: usize) -> Result<Vec<Insn>> {
    let cs = if is_64 {
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
    .map_err(|e| anyhow::anyhow!("capstone init: {:?}", e))?;

    let insns = cs
        .disasm_count(code, base_addr, count)
        .map_err(|e| anyhow::anyhow!("disasm: {:?}", e))?;

    Ok(insns
        .iter()
        .map(|i| Insn {
            addr: i.address(),
            bytes: i.bytes().iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "),
            mnemonic: i.mnemonic().unwrap_or("").to_string(),
            op_str: i.op_str().unwrap_or("").to_string(),
        })
        .collect())
}
