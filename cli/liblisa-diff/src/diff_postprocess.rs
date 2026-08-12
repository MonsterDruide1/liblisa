use crate::diff_types::{Diff, DiffResult};
use crate::state_diff::{DifferenceType, OkMismatch};
use liblisa::arch::{CpuState, x64::{GpReg, X64Arch, X64Flag, X64Reg, X87Reg, XmmReg}};
use liblisa::state::SystemState;
use thiserror::Error;
use xed_sys::*;
use log::error;

#[derive(Debug)]
pub enum ExplainedMismatch {
    /// flag is undefined as per intel manual/XED, CPUs/Ghidra might implement it differently
    UndefinedFlag(String, X64Flag),  // (instruction, flag)
    /// register is undefined as per intel manual/XED, CPUs/Ghidra might implement it differently
    UndefinedReg(String),  // (instruction) - register does not matter, as it will be different per instantiation
    /// AF flag is not handled in Ghidra properly
    AfNotImplemented,
    /// using MMX instructions resets X87 stack (top-of-stack and tag-word), which is not done in Ghidra
    X87ResetOnMMX,
    /// in Ghidra: SHR contains hardcoded `OF = 0`, while specification says
    /// > For the SHR instruction, the OF flag is set to the most-significant bit of the original operand.
    /// > The OF flag is affected only for 1-bit shifts [...]; otherwise, it is undefined.
    /// => already caught as undefined for non-1-bit shifts, so explicitly handle 1-bit shifts here
    SHR1OF,
    /// in Ghidra: PSLL[D,Q] shifts every part of the register by an independent count, while it should actually
    /// be one common count across all of them
    /// Example: 0ff26b00 -r RBX=00 -r mm5=0102030405060708090a
    /// => -m 00=0100000001 : expected: 0x0A090000000000000000, got 0x0A09100E0C0A08060402
    /// => -m 00=0100000000 : expected: 0x0A09100E0C0A08060402, got 0x0A090807060508060402
    /// Note: PSLLW is not implemented (`define pcodeop psllw`), so doesn't have the same problem
    PSLLDQShiftIndependent,
}

impl ExplainedMismatch {
    pub fn description(&self) -> String {
        match self {
            ExplainedMismatch::UndefinedFlag(iclass, flag) => {
                format!("Undefined flag {:?} in instruction {}", flag, iclass)
            }
            ExplainedMismatch::UndefinedReg(iclass) => {
                format!("Undefined register in instruction {}", iclass)
            }
            ExplainedMismatch::AfNotImplemented => {
                "AF flag mismatch is not implemented".to_string()
            }
            ExplainedMismatch::X87ResetOnMMX => {
                "X87 stack reset on MMX instruction is not implemented".to_string()
            }
            ExplainedMismatch::SHR1OF => {
                "Ghidra's implementation of SHR instruction sets OF=0 for 1-bit shifts, while specification says it should be the most-significant bit of the original operand".to_string()
            }
            ExplainedMismatch::PSLLDQShiftIndependent => {
                "Ghidra's implementation of PSLL[D,Q] shifts every part of the register by an independent count, while it should actually be one common count across all of them".to_string()
            }
        }
    }
    pub fn name(&self) -> String {
        match self {
            ExplainedMismatch::UndefinedFlag(_, _) => "UndefinedFlag".to_string(),
            ExplainedMismatch::UndefinedReg(_) => "UndefinedReg".to_string(),
            ExplainedMismatch::AfNotImplemented => "AfNotImplemented".to_string(),
            ExplainedMismatch::X87ResetOnMMX => "X87ResetOnMMX".to_string(),
            ExplainedMismatch::SHR1OF => "SHR1OF".to_string(),
            ExplainedMismatch::PSLLDQShiftIndependent => "PSLLDQShiftIndependent".to_string(),
        }
    }
}

#[derive(Debug)]
pub struct UnexplainedMismatch {
    pub item_index: usize,
    pub diff_index: usize,
    pub diff_type: DifferenceType,
    pub instr: Vec<u8>,
    pub iclass: String,
}

pub unsafe fn postprocess(diff: &Diff) -> (Vec<ExplainedMismatch>, Vec<UnexplainedMismatch>) {
    let mut explained = Vec::new();
    let mut unexplained = Vec::new();

    for (i, item) in diff.items.iter().enumerate() {
        let Some(DiffResult { diffs: Ok(diffs) }) = &item.result else {
            continue;
        };

        for (j, diff) in diffs.iter().enumerate() {
            match &diff.diff_type {
                DifferenceType::OkOk(ref mismatches) => {
                    // NOTE: one instruction might have multiple mismatches, so multiple entries could end up in `explained` and `unexplained`!
                    for mismatch in mismatches {
                        if let Some(explanation) = try_explain_mismatch(mismatch, &diff.example_before) {
                            explained.push(explanation);
                        } else {
                            let diff_type = DifferenceType::OkOk(vec![mismatch.clone()]);
                            unexplained.push(build_unexplained(i, j, diff_type, &diff.example_before));
                        }
                    }
                }
                _ => {
                    unexplained.push(build_unexplained(i, j, diff.diff_type.clone(), &diff.example_before));
                }
            }
        }
    }

    (explained, unexplained)
}

unsafe fn build_unexplained(item_index: usize, diff_index: usize, diff_type: DifferenceType, state: &SystemState<X64Arch>) -> UnexplainedMismatch {
    let instr = get_instruction(&state).unwrap_or(&[]);
    let xed = XedInterface::new(instr).expect("failed to get xed interface");
    let iclass = xed.get_iclass();
    UnexplainedMismatch {
        item_index,
        diff_index,
        diff_type,
        instr: instr.to_vec(),
        iclass,
    }
}

fn get_instruction(state: &SystemState<X64Arch>) -> Option<&[u8]> {
    let pc = CpuState::<X64Arch>::gpreg(state.cpu(), GpReg::Rip);
    state.memory().iter().find_map(|(addr, _, data)| {
        let offset = pc.checked_sub(addr.as_u64())?;
        if (offset as usize) < data.len() {
            Some(&data[offset as usize..])
        } else {
            None
        }
    })
}
fn get_mapped_memory(state: &SystemState<X64Arch>, addr: u64, size: usize) -> Option<Vec<u8>> {
    let start_addr = addr;
    let end_addr = addr.wrapping_add(size as u64);

    let mut data = vec![];
    let mut current_addr = start_addr;
    while current_addr != end_addr {
        let Some((page_addr, _, page_data)) = state.memory().iter().find(|(page_addr, _, page_data)| {
            let page_start = page_addr.as_u64();
            let page_end = page_start.wrapping_add(page_data.len() as u64);
            current_addr >= page_start && current_addr < page_end
        }) else {
            error!("Address 0x{:x} is not mapped in memory", current_addr);
            error!("Mappings: {:?}", state.memory());
            return None;
        };

        let offset = current_addr.checked_sub(page_addr.as_u64()).unwrap() as usize;
        let remaining_bytes = end_addr.wrapping_sub(current_addr) as usize;
        let bytes_to_read = std::cmp::min(remaining_bytes, page_data.len() - offset);
        data.extend_from_slice(&page_data[offset..offset + bytes_to_read]);
        current_addr = current_addr.wrapping_add(bytes_to_read as u64);
    }
    Some(data)
}
fn get_mem_operand(state: &SystemState<X64Arch>, mem_operand: &InstrOperand) -> Option<Vec<u8>> {
    let InstrOperand::Mem { access, seg, base, index, scale, disp, width } = mem_operand else {
        return None;
    };
    if seg.is_some() {
        panic!("Segment registers are not supported in this function. Found: {:?}", seg);
    }

    let base_addr = if let Some(base_reg) = base {
        CpuState::<X64Arch>::gpreg(state.cpu(), *base_reg)
    } else {
        0
    };
    let index_addr = if let Some(index_reg) = index {
        CpuState::<X64Arch>::gpreg(state.cpu(), *index_reg)
    } else {
        0
    };
    let scale_factor = *scale as u64;
    let displacement = disp.unwrap_or(0) as u64;

    let effective_addr = base_addr.wrapping_add(index_addr.wrapping_mul(scale_factor)).wrapping_add(displacement);
    get_mapped_memory(state, effective_addr, *width as usize)
}

unsafe fn get_xed_interface(state: &SystemState<X64Arch>) -> Result<XedInterface, XedError> {
    XedInterface::new(get_instruction(state).unwrap_or(&[]))
}

unsafe fn try_explain_mismatch(mismatch: &OkMismatch, state: &SystemState<X64Arch>) -> Option<ExplainedMismatch> {
    use OkMismatch::*;
    match mismatch {
        FlagsMismatch(flag, _, _) => {
            let xed = get_xed_interface(state).expect("failed to get xed interface");
            if xed.get_undefined_flags().contains(flag) {
                return Some(ExplainedMismatch::UndefinedFlag(xed.get_iclass(), *flag));
            }
            if *flag == X64Flag::Af {
                return Some(ExplainedMismatch::AfNotImplemented);
            }
            if *flag == X64Flag::Of && xed.get_iclass() == "SHR" && xed.get_operands().get(0) == Some(&InstrOperand::ImmUnsigned(1)) {
                return Some(ExplainedMismatch::SHR1OF);
            }
            None
        }
        X87TopOfStackMismatch(ghidra, vm) => {
            if *ghidra == state.cpu.x87.top_of_stack && *vm == 0 {
                return Some(ExplainedMismatch::X87ResetOnMMX);
            }
            None
        }
        X87TagWordMismatch(ghidra, vm) => {
            if *ghidra == state.cpu.x87.tag_word && *vm == 0xff {
                return Some(ExplainedMismatch::X87ResetOnMMX);
            }
            None
        }
        RegMismatch(reg, ghidra, vm) => {
            let xed = get_xed_interface(state).expect("failed to get xed interface");
            let ops = xed.get_operands();

            let is_target_reg = ops.get(0) == Some(&InstrOperand::Reg(Some(X64Reg::GpReg(*reg))));
            let is_source_mem_0 = ops.get(1).is_some_and(|mem| {
                match &mem {
                    InstrOperand::Mem { access, .. } => {
                        *access == MemAccess::READ && get_mem_operand(state, mem).is_some_and(|v| v.iter().all(|&x| x==0))
                    }
                    _ => false,
                }
            });
            if is_target_reg && is_source_mem_0 && xed.get_iclass() == "BSF" {
                return Some(ExplainedMismatch::UndefinedReg(xed.get_iclass()));
            }
            None
        }
        X87RegMismatch(reg, ghidra, vm) => {
            let X87Reg::Fpr(fpr_index) = *reg else {
                panic!("Unexpected X87Reg variant: {:?}", reg);
            };
            let xed = get_xed_interface(state).expect("failed to get xed interface");
            let ops = xed.get_operands();

            let is_target_reg = ops.get(0) == Some(&InstrOperand::Reg(Some(X64Reg::X87(*reg))));
            if is_target_reg && ghidra[9..] == state.cpu.x87.fpr[fpr_index as usize][9..] && vm[9..] == [0xff; 2] {
                return Some(ExplainedMismatch::X87ResetOnMMX);
            }
            if is_target_reg && ["PSLLD", "PSLLQ"].contains(&xed.get_iclass().as_str()) {
                return Some(ExplainedMismatch::PSLLDQShiftIndependent);
            }
            None
        }
        _ => None,
    }
}

#[derive(Error, Debug)]
enum XedError {
    #[error("XED decode error: {0}")]
    DecodeError(String),
}

struct XedInterface {
    inst: xed_decoded_inst_t,
}

#[derive(Debug, Clone, PartialEq)]
enum InstrOperand {
    Reg(Option<X64Reg>),
    Mem {
        access: MemAccess,
        seg: Option<GpReg>,
        base: Option<GpReg>,
        index: Option<GpReg>,
        scale: u8,
        disp: Option<i64>,
        width: u32,
    },
    ImmSigned(i32),
    ImmUnsigned(u64),
    Unk,
}
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct MemAccess: u8 {
        const READ  = 0b01;
        const WRITE = 0b10;
    }
}

unsafe fn c2s(ptr: *const i8) -> String {
    let cstr = std::ffi::CStr::from_ptr(ptr);
    cstr.to_string_lossy().into_owned()
}

impl XedInterface {
    pub unsafe fn init() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            xed_tables_init();
        });
        
    }
    pub unsafe fn new(data: &[u8]) -> Result<Self, XedError> {
        Self::init();

        let mut inst = std::mem::MaybeUninit::<xed_decoded_inst_t>::uninit();
        xed_decoded_inst_zero(inst.as_mut_ptr());
        xed_decoded_inst_set_mode(inst.as_mut_ptr(), XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
        let xed_error: xed_error_enum_t = xed_decode(inst.as_mut_ptr(), data.as_ptr(), data.len() as u32);
        if xed_error != XED_ERROR_NONE {
            return Err(XedError::DecodeError(c2s(xed_error_enum_t2str(xed_error))));
        }
        Ok(Self {
            inst: inst.assume_init(),
        })
    }

    pub unsafe fn get_iclass(&self) -> String {
        return c2s(xed_iclass_enum_t2str(xed_decoded_inst_get_iclass(&self.inst)));
    }

    pub unsafe fn get_undefined_flags(&self) -> Vec<X64Flag> {
        let rflags_info = xed_decoded_inst_get_rflags_info(&self.inst);
        let undef_flags = xed_simple_flag_get_undefined_flag_set(rflags_info);
        let mut flags = Vec::new();
        if (*undef_flags).s.cf() != 0 {
            flags.push(X64Flag::Cf);
        }
        if (*undef_flags).s.pf() != 0 {
            flags.push(X64Flag::Pf);
        }
        if (*undef_flags).s.af() != 0 {
            flags.push(X64Flag::Af);
        }
        if (*undef_flags).s.zf() != 0 {
            flags.push(X64Flag::Zf);
        }
        if (*undef_flags).s.sf() != 0 {
            flags.push(X64Flag::Sf);
        }
        if (*undef_flags).s.of() != 0 {
            flags.push(X64Flag::Of);
        }
        flags
    }

    // note: this function is very specific to the current use case
    // and might be generalized in the future
    pub unsafe fn get_operands(&self) -> Vec<InstrOperand> {
        let xi = xed_decoded_inst_inst(&self.inst);
        let mut operands = Vec::new();
        for i in 0..xed_inst_noperands(xi) {
            let operand_name: xed_operand_enum_t = xed_operand_name(xed_inst_operand(xi, i));
            match operand_name {
                XED_OPERAND_REG0 | XED_OPERAND_REG1 | XED_OPERAND_REG2 | XED_OPERAND_REG3 | XED_OPERAND_REG4 | XED_OPERAND_REG5 | XED_OPERAND_REG6 | XED_OPERAND_REG7 => {
                    let reg = Self::xed_reg_to_x64reg(xed_decoded_inst_get_reg(&self.inst, operand_name));
                    operands.push(InstrOperand::Reg(reg));
                },
                XED_OPERAND_IMM0 => {
                    if xed_decoded_inst_get_immediate_is_signed(&self.inst) != 0 {
                        let imm = xed_decoded_inst_get_signed_immediate(&self.inst);
                        operands.push(InstrOperand::ImmSigned(imm));
                    } else {
                        let imm = xed_decoded_inst_get_unsigned_immediate(&self.inst);
                        operands.push(InstrOperand::ImmUnsigned(imm));
                    }
                },
                XED_OPERAND_MEM0 | XED_OPERAND_MEM1 => {
                    let mem_idx = if operand_name == XED_OPERAND_MEM0 { 0 } else { 1 };
                    let mut access = MemAccess::empty();
                    if xed_decoded_inst_mem_read(&self.inst, mem_idx) != 0 {
                        access |= MemAccess::READ;
                    }
                    if xed_decoded_inst_mem_written(&self.inst, mem_idx) != 0 {
                        access |= MemAccess::WRITE;
                    }
                    let x2g = |x| {
                        match Self::xed_reg_to_x64reg(x) {
                            None => None,
                            Some(X64Reg::GpReg(g)) => Some(g),
                            _ => panic!("Unexpected register type: {:?}", x),
                        }
                    };
                    let seg = x2g(xed_decoded_inst_get_seg_reg(&self.inst, mem_idx));
                    let base = x2g(xed_decoded_inst_get_base_reg(&self.inst, mem_idx));
                    let index = x2g(xed_decoded_inst_get_index_reg(&self.inst, mem_idx));
                    let scale = xed_decoded_inst_get_scale(&self.inst, mem_idx) as u8;
                    let disp = if xed_operand_values_has_memory_displacement(&self.inst) != 0 {
                        Some(xed_decoded_inst_get_memory_displacement(&self.inst, mem_idx))
                    } else { None };
                    let width = xed_decoded_inst_get_memory_operand_length(&self.inst,mem_idx);

                    operands.push(InstrOperand::Mem { access, seg, base, index, scale, disp, width });
                },
                _ => continue,
            }
        }
        operands
    }

    fn xed_reg_to_x64reg(reg: xed_reg_enum_t) -> Option<X64Reg> {
        match reg {
            XED_REG_RAX | XED_REG_EAX | XED_REG_AX | XED_REG_AH | XED_REG_AL => Some(X64Reg::GpReg(GpReg::Rax)),
            XED_REG_RCX | XED_REG_ECX | XED_REG_CX | XED_REG_CH | XED_REG_CL => Some(X64Reg::GpReg(GpReg::Rcx)),
            XED_REG_RDX | XED_REG_EDX | XED_REG_DX | XED_REG_DH | XED_REG_DL => Some(X64Reg::GpReg(GpReg::Rdx)),
            XED_REG_RSI | XED_REG_ESI | XED_REG_SI | XED_REG_SIL => Some(X64Reg::GpReg(GpReg::Rsi)),
            XED_REG_RDI | XED_REG_EDI | XED_REG_DI | XED_REG_DIL => Some(X64Reg::GpReg(GpReg::Rdi)),
            XED_REG_RIP | XED_REG_EIP | XED_REG_IP => Some(X64Reg::GpReg(GpReg::Rip)),
            XED_REG_RBP | XED_REG_EBP | XED_REG_BP => Some(X64Reg::GpReg(GpReg::Rbp)),
            XED_REG_RBX | XED_REG_EBX | XED_REG_BX | XED_REG_BH | XED_REG_BL => Some(X64Reg::GpReg(GpReg::Rbx)),
            XED_REG_RSP | XED_REG_ESP | XED_REG_SP | XED_REG_SPL => Some(X64Reg::GpReg(GpReg::Rsp)),
            XED_REG_R8 | XED_REG_R8D | XED_REG_R8W | XED_REG_R8B => Some(X64Reg::GpReg(GpReg::R8)),
            XED_REG_R9 | XED_REG_R9D | XED_REG_R9W | XED_REG_R9B => Some(X64Reg::GpReg(GpReg::R9)),
            XED_REG_R10 | XED_REG_R10D | XED_REG_R10W | XED_REG_R10B => Some(X64Reg::GpReg(GpReg::R10)),
            XED_REG_R11 | XED_REG_R11D | XED_REG_R11W | XED_REG_R11B => Some(X64Reg::GpReg(GpReg::R11)),
            XED_REG_R12 | XED_REG_R12D | XED_REG_R12W | XED_REG_R12B => Some(X64Reg::GpReg(GpReg::R12)),
            XED_REG_R13 | XED_REG_R13D | XED_REG_R13W | XED_REG_R13B => Some(X64Reg::GpReg(GpReg::R13)),
            XED_REG_R14 | XED_REG_R14D | XED_REG_R14W | XED_REG_R14B => Some(X64Reg::GpReg(GpReg::R14)),
            XED_REG_R15 | XED_REG_R15D | XED_REG_R15W | XED_REG_R15B => Some(X64Reg::GpReg(GpReg::R15)),
            XED_REG_FSBASE => Some(X64Reg::GpReg(GpReg::FsBase)),
            XED_REG_GSBASE => Some(X64Reg::GpReg(GpReg::GsBase)),
            XED_REG_RFLAGS => Some(X64Reg::GpReg(GpReg::RFlags)),
            // Riz doesn't exist in XED

            XED_REG_MMX0 => Some(X64Reg::X87(X87Reg::Fpr(0))),
            XED_REG_MMX1 => Some(X64Reg::X87(X87Reg::Fpr(1))),
            XED_REG_MMX2 => Some(X64Reg::X87(X87Reg::Fpr(2))),
            XED_REG_MMX3 => Some(X64Reg::X87(X87Reg::Fpr(3))),
            XED_REG_MMX4 => Some(X64Reg::X87(X87Reg::Fpr(4))),
            XED_REG_MMX5 => Some(X64Reg::X87(X87Reg::Fpr(5))),
            XED_REG_MMX6 => Some(X64Reg::X87(X87Reg::Fpr(6))),
            XED_REG_MMX7 => Some(X64Reg::X87(X87Reg::Fpr(7))),

            XED_REG_XMM0 => Some(X64Reg::Xmm(XmmReg::Reg(0))),
            XED_REG_XMM1 => Some(X64Reg::Xmm(XmmReg::Reg(1))),
            XED_REG_XMM2 => Some(X64Reg::Xmm(XmmReg::Reg(2))),
            XED_REG_XMM3 => Some(X64Reg::Xmm(XmmReg::Reg(3))),
            XED_REG_XMM4 => Some(X64Reg::Xmm(XmmReg::Reg(4))),
            XED_REG_XMM5 => Some(X64Reg::Xmm(XmmReg::Reg(5))),
            XED_REG_XMM6 => Some(X64Reg::Xmm(XmmReg::Reg(6))),
            XED_REG_XMM7 => Some(X64Reg::Xmm(XmmReg::Reg(7))),
            XED_REG_XMM8 => Some(X64Reg::Xmm(XmmReg::Reg(8))),
            XED_REG_XMM9 => Some(X64Reg::Xmm(XmmReg::Reg(9))),
            XED_REG_XMM10 => Some(X64Reg::Xmm(XmmReg::Reg(10))),
            XED_REG_XMM11 => Some(X64Reg::Xmm(XmmReg::Reg(11))),
            XED_REG_XMM12 => Some(X64Reg::Xmm(XmmReg::Reg(12))),
            XED_REG_XMM13 => Some(X64Reg::Xmm(XmmReg::Reg(13))),
            XED_REG_XMM14 => Some(X64Reg::Xmm(XmmReg::Reg(14))),
            XED_REG_XMM15 => Some(X64Reg::Xmm(XmmReg::Reg(15))),

            XED_REG_INVALID => None,
            _ => {
                error!("XED register {:?} not mapped to X64Reg", reg);
                None
            }
        }
    }
}
