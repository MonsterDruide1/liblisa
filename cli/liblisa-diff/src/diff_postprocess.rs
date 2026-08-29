use crate::diff_types::{Diff, DiffResult};
use crate::state_diff::{Difference, DifferenceType, OkMismatch};
use liblisa::arch::{CpuState, x64::{GpReg, X64Arch, X64Flag, X87Reg, XmmReg}};
use liblisa::oracle::OracleError;
use liblisa::state::{Addr, SystemState};
use serde::Serialize;
use thiserror::Error;
use xed_sys::*;
use log::error;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum ExplainedMismatch {
    /// flag is undefined as per intel manual/XED, CPUs/Ghidra might implement it differently
    UndefinedFlag(String, X64Flag),  // (instruction, flag)
    /// for instructions using 32-bit registers as target, the upper 32 bits of the registers should be zero-extended,
    /// which is not done properly for some instructions in Ghidra. [Intel, 3.4.1.1]:
    /// > 32-bit operands generate a 32-bit result, zero-extended to a 64-bit result in the destination general-purpose register
    /// in Ghidra, this zero-extension is done manually through `build check_Reg32_dest;`, which is missing for some instructions.
    Reg32NotZeroExtended,
    /// AF flag is not handled in Ghidra properly
    AfNotImplemented,
    /// using MMX instructions resets X87 stack (top-of-stack and tag-word), which is not done in Ghidra
    X87ResetOnMMX,
    /// tag words cannot really be diffed, because Ghidra and the CPU do not match in their representation presented to LibLISA
    /// Ghidra: raw 2-byte tag word, 2 bits per register indicating state
    /// CPU: abridged version with 1 bit per register, as given by XSAVE
    /// this manifests in diffs relating to the tag word, and potentially even some instructions where the tag word is used as input data
    /// no relevant instructions of the latter kind are implemented in Ghidra at the moment though
    X87TagWordRepresentationMismatch,        
    /// x87 exception flags contains a summary bit, which is set when any exception bit is set: [Intel, 8.1.3.3]
    /// > The exception summary status flag (ES, bit 7) is set when any of the unmasked exception flags are set.
    /// on CPUs, this is sometimes updated automatically, while Ghidra usually keeps it unchanged
    X87ExceptionSummaryFlagOutdated,
    /// From Ghidra's `ia.sinc`:
    /// > attach variables [ xmmreg1_r xmmreg2_x ] [ XMM16 XMM17 XMM18 XMM19 XMM20 XMM21 XMM22 XMM23 ];
    /// > XmmReg1:  xmmreg1_r  is rexRprefix=0 & evexRp=1 & xmmreg1_r             { export xmmreg1_r; }   // <- correct: requires evex
    /// > XmmReg2:  xmmreg2_x is rexBprefix=0 & rexXprefix=1 & xmmreg2_x          { export xmmreg2_x; }   // <- incorrect: no evex required
    /// this causes the `rex.X` prefix to change the target register in Ghidra, when it should have no effect instead.
    /// for reference: XMM16..31 should only be accessible through VEX extensions
    UpperXMMThroughRexX,
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
    /// in Ghidra: PINSRW with mmx register uses more than the two least-significant bits to determine the target
    /// Ghidra: `local destIndex:1 = (imm8 & 0x7) * 16:1;`
    /// Spec: `When specifying a word location in an MMX technology register, the 2 least-significant bits of the count operand specify the location;`
    /// Note: other variants of PINSR[.] as well as PINSRW with XMM register are implemented correctly
    PINSRWMMXImmTooLarge,
    /// Division can go out-of-range of resulting type, which will cause ComputationError on CPU
    /// while Ghidra only cuts off the result to the resulting type
    /// happens for example on `0xffff / 0xf7`
    DivOutOfRange,
    /// XADD has the following setup in Ghidra: `Reg8 = m8; m8 = tmp;`
    /// when Reg8 and m8 use the same register, this will cause the second write to end up at a different location than intended
    /// the result can be anything from ineffective writes, shifted results up to a page fault (=> unmapped new target)
    /// similar for BLSI (32 and 64-bit variants): `vexVVVV_r64 = -rm64 & rm64;`, followed by `CF = (rm64 != 0);` => wrong address
    RegisterConflict,
    /// ENTER seems to be implemented incorrectly on Intel i5-8365U:
    /// it treats the first operand (imm16) as signed instead of unsigned
    /// Ghidra is correct here, and it seems to be limited to this single CPU from my test set
    EnterCPUWrongSigned,
    /// for MOV reg, sreg, Ghidra only copies over the lower 16 bits, leaving the upper 48 bits unchanged.
    /// Specification says that upper bits should usually be zero-extended (unless older generations of 32-bit CPUs):
    /// > The upper bits of the destination register are zero for most IA-32 processors (Pentium Pro processors and later)
    /// > and all Intel 64 processors, with the exception that bits 31:16 are undefined for Intel Quark X1000 processors,
    /// > Pentium, and earlier processors.
    MovSRegNonZeroExtended,
    /// NOPs with REX prefix end up as `REX XCHG eax, eax` in Ghidra, which causes the top 32 bits to be shaved off. Spec:
    /// > XCHG (E)AX, (E)AX (encoded instruction byte is 90H) is an alias for NOP regardless of data size prefixes, including REX.W.
    /// => should still do nothing, Ghidra does not treat this special case right
    RexNopDiscardsHighBytes,
    /// LAR is supposed to read GDT and permission tables, which just don't exist in Ghidra
    /// instead, Ghidra models it as simple read from the address, which is plain wrong and results in many potential mismatches
    LarNotImplemented,
    /// BSF/BSR specify target register to be undefined (intel, pre-2024-10-11) or unchanged (intel, current ; amd) if source operand is zero
    /// Ghidra instead overwrites it with zero, which is incorrect
    BsfBsrSourceOperandZero,
}

impl ExplainedMismatch {
    pub fn description(&self) -> String {
        match self {
            ExplainedMismatch::UndefinedFlag(iclass, flag) => {
                format!("Undefined flag {:?} in instruction {}", flag, iclass)
            }
            ExplainedMismatch::Reg32NotZeroExtended => {
                "Ghidra does not zero-extend the upper 32 bits of 32-bit register results".to_string()
            }
            ExplainedMismatch::AfNotImplemented => {
                "AF flag mismatch is not implemented".to_string()
            }
            ExplainedMismatch::X87ResetOnMMX => {
                "X87 stack reset on MMX instruction is not implemented".to_string()
            }
            ExplainedMismatch::X87TagWordRepresentationMismatch => {
                "The representation of tag words differs between Ghidra and CPU, so no diffs can be made here".to_string()
            }
            ExplainedMismatch::X87ExceptionSummaryFlagOutdated => {
                "Ghidra's implementation of X87 exception summary flag is outdated".to_string()
            }
            ExplainedMismatch::UpperXMMThroughRexX => {
                "Ghidra's implementation of REX.X prefix allows access to upper XMM registers, while it should not".to_string()
            }
            ExplainedMismatch::SHR1OF => {
                "Ghidra's implementation of SHR instruction sets OF=0 for 1-bit shifts, while specification says it should be the most-significant bit of the original operand".to_string()
            }
            ExplainedMismatch::PSLLDQShiftIndependent => {
                "Ghidra's implementation of PSLL[D,Q] shifts every part of the register by an independent count, while it should actually be one common count across all of them".to_string()
            }
            ExplainedMismatch::PINSRWMMXImmTooLarge => {
                "Ghidra's implementation of PINSRW with MMX register uses more than the two least-significant bits to determine the target".to_string()
            }
            ExplainedMismatch::DivOutOfRange => {
                "Division result is out-of-range of resulting type".to_string()
            }
            ExplainedMismatch::RegisterConflict => {
                "Using the same register for source and target with a memory operand can malfunction in Ghidra".to_string()
            }
            ExplainedMismatch::EnterCPUWrongSigned => {
                "Intel i5-8365U CPU treats the first operand of ENTER as signed instead of unsigned, while Ghidra is correct".to_string()
            }
            ExplainedMismatch::MovSRegNonZeroExtended => {
                "Ghidra's implementation of MOV reg, sreg only copies over the lower 16 bits, leaving the upper 48 bits unchanged".to_string()
            }
            ExplainedMismatch::RexNopDiscardsHighBytes => {
                "NOPs with REX prefix end up as `REX XCHG eax, eax` in Ghidra, which causes the top 32 bits to be shaved off".to_string()
            }
            ExplainedMismatch::LarNotImplemented => {
                "LAR is supposed to read GDT and permission tables, which just don't exist in Ghidra".to_string()
            }
            ExplainedMismatch::BsfBsrSourceOperandZero => {
                "BSF/BSR with a zero source operand should leave the target register undefined, but Ghidra overwrites it with zero".to_string()
            }
        }
    }
    pub fn name(&self) -> String {
        match self {
            ExplainedMismatch::UndefinedFlag(_, _) => "UndefinedFlag".to_string(),
            ExplainedMismatch::Reg32NotZeroExtended => "Reg32NotZeroExtended".to_string(),
            ExplainedMismatch::AfNotImplemented => "AfNotImplemented".to_string(),
            ExplainedMismatch::X87ResetOnMMX => "X87ResetOnMMX".to_string(),
            ExplainedMismatch::X87TagWordRepresentationMismatch => "X87TagWordRepresentationMismatch".to_string(),
            ExplainedMismatch::X87ExceptionSummaryFlagOutdated => "X87ExceptionSummaryFlagOutdated".to_string(),
            ExplainedMismatch::UpperXMMThroughRexX => "UpperXMMThroughRexX".to_string(),
            ExplainedMismatch::SHR1OF => "SHR1OF".to_string(),
            ExplainedMismatch::PSLLDQShiftIndependent => "PSLLDQShiftIndependent".to_string(),
            ExplainedMismatch::PINSRWMMXImmTooLarge => "PINSRWMMXImmTooLarge".to_string(),
            ExplainedMismatch::DivOutOfRange => "DivOutOfRange".to_string(),
            ExplainedMismatch::RegisterConflict => "RegisterConflict".to_string(),
            ExplainedMismatch::EnterCPUWrongSigned => "EnterCPUWrongSigned".to_string(),
            ExplainedMismatch::MovSRegNonZeroExtended => "MovSRegNonZeroExtended".to_string(),
            ExplainedMismatch::RexNopDiscardsHighBytes => "RexNopDiscardsHighBytes".to_string(),
            ExplainedMismatch::LarNotImplemented => "LarNotImplemented".to_string(),
            ExplainedMismatch::BsfBsrSourceOperandZero => "BsfBsrSourceOperandZero".to_string(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct UnexplainedMismatch {
    pub item_index: usize,
    pub diff_index: usize,
    pub diff_type: DifferenceType,
    pub instr: Vec<u8>,
    pub iclass: String,
}

pub unsafe fn postprocess_all(diff: &Diff) -> (Vec<ExplainedMismatch>, Vec<UnexplainedMismatch>) {
    let mut explained = Vec::new();
    let mut unexplained = Vec::new();

    for (i, item) in diff.items.iter().enumerate() {
        let Some(DiffResult { diffs: Ok(diffs) }) = &item.result else {
            continue;
        };

        for (j, diff) in diffs.iter().enumerate() {
            let (explained_mismatches, unexplained_mismatches) = try_explain_diff(diff, i, j);
            explained.extend(explained_mismatches);
            unexplained.extend(unexplained_mismatches);
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
            let page_end = page_start.checked_add((page_data.len()-1) as u64).unwrap();
            current_addr >= page_start && current_addr <= page_end
        }) else {
            error!("Address 0x{:x} is not mapped in memory", current_addr);
            error!("Mappings: {:?}", state.memory());
            return None;
        };

        let offset = current_addr.checked_sub(page_addr.as_u64()).unwrap() as usize;
        let remaining_bytes = end_addr.wrapping_sub(current_addr) as usize;
        let bytes_to_read = std::cmp::min(remaining_bytes, page_data.len() - offset);
        data.extend_from_slice(&page_data[offset..offset.checked_add(bytes_to_read).unwrap()]);
        current_addr = current_addr.wrapping_add(bytes_to_read as u64);
    }
    Some(data)
}
fn get_mem_operand_addr(state: &SystemState<X64Arch>, mem_operand: &InstrOperand) -> Option<(u64, usize)> {
    // copy state and adjust RIP to point to after instruction
    // relevant for memory accesses with RIP-relative addressing (or using RIP as index, ...)
    let mut state = state.clone();
    let pc = CpuState::<X64Arch>::gpreg(state.cpu(), GpReg::Rip);
    let new_pc = pc.wrapping_add(get_instruction(&state).unwrap_or(&[]).len() as u64);
    CpuState::<X64Arch>::set_gpreg(state.cpu_mut(), GpReg::Rip, new_pc);

    let InstrOperand::Mem { seg, base, index, scale, disp, width, .. } = mem_operand else {
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
    Some((effective_addr, *width as usize))
}
fn get_mem_operand(state: &SystemState<X64Arch>, mem_operand: &InstrOperand) -> Option<Vec<u8>> {
    let (addr, size) = get_mem_operand_addr(state, mem_operand)?;
    get_mapped_memory(&state, addr, size)
}

unsafe fn get_xed_interface(state: &SystemState<X64Arch>) -> Result<XedInterface, XedError> {
    XedInterface::new(get_instruction(state).unwrap_or(&[]))
}

pub unsafe fn try_explain_diff(diff: &Difference, item_index: usize, diff_index: usize) -> (Vec<ExplainedMismatch>, Vec<UnexplainedMismatch>) {
    match &diff.diff_type {
        DifferenceType::OkOk(ref mismatches) => {
            // NOTE: one instruction might have multiple mismatches, so multiple entries could end up in `explained` and `unexplained`!
            let mut explained = vec![];
            let mut unexplained = vec![];
            for mismatch in mismatches {
                if let Some(explanation) = try_explain_okmismatch(mismatch, &diff.example_before) {
                    explained.push(explanation);
                } else {
                    let diff_type = DifferenceType::OkOk(vec![mismatch.clone()]);
                    unexplained.push(build_unexplained(item_index, diff_index, diff_type, &diff.example_before));
                }
            }
            explained.sort();
            explained.dedup();
            return (explained, unexplained);
        },
        DifferenceType::OkErr(OracleError::ComputationError) => {
            if is_xadd_register_conflict(&diff.example_before, None) {
                return (vec![ExplainedMismatch::RegisterConflict], vec![]);
            }
            let xed = get_xed_interface(&diff.example_before).expect("failed to get xed interface");
            if ["DIV", "IDIV"].contains(&xed.get_iclass().as_str()) {
                return (vec![ExplainedMismatch::DivOutOfRange], vec![]);
            }
        },
        DifferenceType::ErrOk(OracleError::MemoryAccess(addr)) => {
            if is_xadd_register_conflict(&diff.example_before, None) {
                return (vec![ExplainedMismatch::RegisterConflict], vec![]);
            }
            let xed = get_xed_interface(&diff.example_before).expect("failed to get xed interface");
            if xed.get_iclass() == "LAR" && get_mem_operand_addr(&diff.example_before, &xed.get_operands()[1]).is_some_and(|(a, _)| addr.distance_between(Addr::new(a)) < 8) {
                return (vec![ExplainedMismatch::LarNotImplemented], vec![]);
            }
        },
        _ => {
            if is_xadd_register_conflict(&diff.example_before, None) {
                return (vec![ExplainedMismatch::RegisterConflict], vec![]);
            }
        },
    }
    
    return (vec![], vec![build_unexplained(item_index, diff_index, diff.diff_type.clone(), &diff.example_before)]);
}

unsafe fn try_explain_okmismatch(mismatch: &OkMismatch, state: &SystemState<X64Arch>) -> Option<ExplainedMismatch> {
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
            if *flag == X64Flag::Of && xed.get_iclass() == "SHR" && xed.get_operands().get(1) == Some(&InstrOperand::ImmUnsigned(1)) {
                return Some(ExplainedMismatch::SHR1OF);
            }
            if is_xadd_register_conflict(state, None) {
                return Some(ExplainedMismatch::RegisterConflict);
            }
            if *flag == X64Flag::Zf && xed.get_iclass() == "LAR" {
                return Some(ExplainedMismatch::LarNotImplemented);
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
            Some(ExplainedMismatch::X87TagWordRepresentationMismatch)
        }
        X87ExceptionFlagsMismatch(ghidra, vm) => {
            let exception_summary_mask = 0xff << (7*8);
            // if everything *but* exception summary mask matches
            // note: ghidra might not maintain old value if `FLDENV` or similar is executed
            if (vm & !exception_summary_mask) == (ghidra & !exception_summary_mask) {
                return Some(ExplainedMismatch::X87ExceptionSummaryFlagOutdated);
            }
            None
        }
        RegMismatch(reg, ghidra, vm) => {
            let xed = get_xed_interface(state).expect("failed to get xed interface");
            let ops = xed.get_operands();

            let target_regs = if xed.get_iclass() == "XADD" {
                vec![ops.get(1).unwrap()]
            } else if xed.get_iclass() == "CMPXCHG8B" {
                assert!(ops.get(1).unwrap().is_reg(&GpReg::Rdx));
                assert!(ops.get(2).unwrap().is_reg(&GpReg::Rax));
                vec![ops.get(1).unwrap(), ops.get(2).unwrap()]
            } else {
                if let Some(x) = ops.get(0) { vec![x] } else { vec![] }
            };
            for target_reg in target_regs {
                if let InstrOperand::Reg(InstrOperandReg::GpReg { reg: r, width, .. }) = target_reg {
                    let mask = 0x00000000ffffffff;
                    if reg == r && *width == 4 && (vm & !mask) == 0 && (ghidra & mask) == (vm & mask) {
                        return Some(ExplainedMismatch::Reg32NotZeroExtended);
                    }
                }
            }

            let is_target_reg = ops.get(0).is_some_and(|op| op.is_reg(reg));
            let is_source_mem_0 = ops.get(1).is_some_and(|mem| {
                match &mem {
                    InstrOperand::Mem { access, .. } => {
                        access.contains(MemAccess::READ) && get_mem_operand(state, mem).is_some_and(|v| v.iter().all(|&x| x==0))
                    }
                    _ => false,
                }
            });
            let is_source_reg_0 = ops.get(1).map_or(false, |op| {
                op.get_reg_value(state).is_some_and(|v| v == 0)
            });
            if is_target_reg && (is_source_mem_0 || is_source_reg_0) && ["BSF", "BSR"].contains(&xed.get_iclass().as_str()) {
                return Some(ExplainedMismatch::BsfBsrSourceOperandZero);
            }
            if is_xadd_register_conflict(state, Some(reg)) {
                return Some(ExplainedMismatch::RegisterConflict);
            }

            if reg == &GpReg::Rsp && xed.get_iclass() == "ENTER" && (|| {
                let Some(InstrOperand::ImmUnsigned(imm)) = ops.get(0) else { return false; };
                let imm = *imm as u16;
                let Some(InstrOperand::SecondImm(nesting)) = ops.get(1) else { return false; };
                let nesting = nesting % 32;

                let rsp_before = CpuState::<X64Arch>::gpreg(state.cpu(), GpReg::Rsp);
                let rsp = rsp_before.wrapping_sub(8).wrapping_sub(nesting as u64 * 8);
                let correct_rsp = rsp.wrapping_sub(imm as u64);
                let faulty_rsp = rsp.wrapping_sub(imm.cast_signed() as u64);
                *ghidra == correct_rsp && *vm == faulty_rsp
            })() {
                return Some(ExplainedMismatch::EnterCPUWrongSigned);
            }

            if is_target_reg && xed.is_operand_sreg(1) && xed.get_iclass() == "MOV" {
                let reg_before = CpuState::<X64Arch>::gpreg(state.cpu(), *reg);
                let mask = 0xffff;
                // high bits of vm are 0, high bits of ghidra are unchanged, low bits are identical
                if (vm & !mask) == 0 && (reg_before & !mask) == (ghidra & !mask) && (ghidra & mask) == (vm & mask) {
                    return Some(ExplainedMismatch::MovSRegNonZeroExtended);
                }
            }

            if *reg == GpReg::Rax && xed.get_iclass() == "NOP" {
                let reg_before = CpuState::<X64Arch>::gpreg(state.cpu(), *reg);
                let mask = 0xffffffff;
                // vm is unchanged, ghidra is cut off to 32 bits
                if *vm == reg_before && (ghidra & mask) == (reg_before & mask) && (ghidra & !mask) == 0 {
                    return Some(ExplainedMismatch::RexNopDiscardsHighBytes);
                }
            }

            if is_target_reg && xed.get_iclass() == "LAR" {
                return Some(ExplainedMismatch::LarNotImplemented);
            }

            None
        }
        X87RegMismatch(reg, ghidra, vm) => {
            let X87Reg::Fpr(fpr_index) = *reg else {
                panic!("Unexpected X87Reg variant: {:?}", reg);
            };
            let xed = get_xed_interface(state).expect("failed to get xed interface");
            let ops = xed.get_operands();

            let is_target_reg = ops.get(0).is_some_and(|op| op.is_x87_reg(reg));
            if is_target_reg && ghidra[..8] == vm[..8] && ghidra[8..] == state.cpu.x87.fpr[fpr_index as usize][8..] && vm[8..] == [0xff; 2] {
                return Some(ExplainedMismatch::X87ResetOnMMX);
            }
            if is_target_reg && ["PSLLD", "PSLLQ"].contains(&xed.get_iclass().as_str()) {
                return Some(ExplainedMismatch::PSLLDQShiftIndependent);
            }
            if is_target_reg && xed.get_iclass() == "PINSRW" && ops.get(2).is_some_and(|x| {
                let InstrOperand::ImmUnsigned(imm) = x else { return false; };
                (imm & 0x4) != 0
                // lowest two bits are considered correctly, but Ghidra includes third bit as well
                // => only wrong if the third bit is set
            }) {
                return Some(ExplainedMismatch::PINSRWMMXImmTooLarge);
            }
            None
        }
        MemoryMismatch(_, _, _) => {
            if is_xadd_register_conflict(state, None) {
                return Some(ExplainedMismatch::RegisterConflict);
            }
            None
        }
        XmmMismatch(_, _, _) => {
            let xed = get_xed_interface(state).expect("failed to get xed interface");

            // not really a way to check closer, as wrong register could be taken as input or output, and the result could be anything
            if xed.is_rex() {
                return Some(ExplainedMismatch::UpperXMMThroughRexX);
            }
            None
        }
        _ => None,
    }
}

unsafe fn is_xadd_register_conflict(state: &SystemState<X64Arch>, mismatching_reg: Option<&GpReg>) -> bool {
    let xed = get_xed_interface(state).expect("failed to get xed interface");
    let ops = xed.get_operands();
    let (mem_operand, reg_operand) = if xed.get_iclass() == "XADD" {
        (ops.get(0), ops.get(1))
    } else if xed.get_iclass() == "BLSI" {
        (ops.get(1), ops.get(0))
    } else {
        return false;
    };

    let Some(InstrOperand::Reg(InstrOperandReg::GpReg { reg, .. })) = reg_operand else {
        error!("Unexpected reg_operand type for register conflict on {}: {:?}", xed.get_iclass(), reg_operand);
        return false;
    };
    let Some(InstrOperand::Mem{ seg, base, index, .. }) = mem_operand else {
        error!("Unexpected mem_operand type for register conflict on {}: {:?}", xed.get_iclass(), mem_operand);
        return false;
    };

    if mismatching_reg.is_some_and(|r| r != reg) {
        return false;
    }

    if seg.is_some_and(|s| *reg == s) {
        return true;
    }
    if base.is_some_and(|b| *reg == b) {
        return true;
    }
    if index.is_some_and(|i| *reg == i) {
        return true;
    }
    false
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
enum InstrOperandReg {
    GpReg {
        reg: GpReg,
        width: u8,  // in bytes
        offset: u8,  // in bytes
    },
    XmmReg(XmmReg),
    X87Reg(X87Reg),
    SReg(&'static str),
    X87Status,
    X87Control,
    StackPush,
    ControlReg(u8),
    Unk,
}

#[derive(Debug, Clone, PartialEq)]
enum InstrOperand {
    Reg(InstrOperandReg),
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
    SecondImm(u8),
    Unk,
}
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct MemAccess: u8 {
        const READ  = 0b01;
        const WRITE = 0b10;
    }
}

impl InstrOperand {
    fn get_width_mask(width: u8) -> u64 {
        match width {
            1 => 0xff,
            2 => 0xffff,
            4 => 0xffffffff,
            8 => 0xffffffffffffffff,
            _ => panic!("Unsupported width: {}", width),
        }
    }

    pub fn is_reg(&self, reg: &GpReg) -> bool {
        match self {
            InstrOperand::Reg(InstrOperandReg::GpReg { reg: r, .. }) => r == reg,
            _ => false,
        }
    }
    pub fn is_x87_reg(&self, reg: &X87Reg) -> bool {
        match self {
            InstrOperand::Reg(InstrOperandReg::X87Reg(r)) => r == reg,
            _ => false,
        }
    }
    pub fn is_xmm_reg(&self, reg: &XmmReg) -> bool {
        match self {
            InstrOperand::Reg(InstrOperandReg::XmmReg(r)) => r == reg,
            _ => false,
        }
    }
    pub fn get_reg_value(&self, state: &SystemState<X64Arch>) -> Option<u64> {
        match self {
            InstrOperand::Reg(InstrOperandReg::GpReg { reg, width, offset }) => {
                let value = CpuState::<X64Arch>::gpreg(state.cpu(), *reg);
                Some((value >> (offset * 8)) & Self::get_width_mask(*width))
            }
            _ => None,
        }
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

    pub unsafe fn is_rex(&self) -> bool {
        xed3_operand_get_rexx(&self.inst) != 0
    }

    // note: this function is very specific to the current use case
    // and might be generalized in the future
    pub unsafe fn get_operands(&self) -> Vec<InstrOperand> {
        let xi = xed_decoded_inst_inst(&self.inst);
        let mut operands = Vec::new();
        for i in 0..xed_inst_noperands(xi) {
            let operand_name: xed_operand_enum_t = xed_operand_name(xed_inst_operand(xi, i));
            let operand = match operand_name {
                XED_OPERAND_REG0 | XED_OPERAND_REG1 | XED_OPERAND_REG2 | XED_OPERAND_REG3 | XED_OPERAND_REG4 | XED_OPERAND_REG5 | XED_OPERAND_REG6 | XED_OPERAND_REG7 => {
                    let reg = Self::xed_reg_to_opreg(xed_decoded_inst_get_reg(&self.inst, operand_name));
                    InstrOperand::Reg(reg)
                },
                XED_OPERAND_IMM0 => {
                    if xed_decoded_inst_get_immediate_is_signed(&self.inst) != 0 {
                        let imm = xed_decoded_inst_get_signed_immediate(&self.inst);
                        InstrOperand::ImmSigned(imm)
                    } else {
                        let imm = xed_decoded_inst_get_unsigned_immediate(&self.inst);
                        InstrOperand::ImmUnsigned(imm)
                    }
                },
                XED_OPERAND_IMM1 => {
                    // second immediate is always 1 byte, unsigned
                    InstrOperand::SecondImm(xed_decoded_inst_get_second_immediate(&self.inst))
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
                        if x == XED_REG_INVALID {
                            return None;
                        }
                        match Self::xed_reg_to_opreg(x) {
                            InstrOperandReg::GpReg { reg: g, .. } => Some(g),
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

                    InstrOperand::Mem { access, seg, base, index, scale, disp, width }
                },
                _ => InstrOperand::Unk,
            };
            operands.push(operand);
        }
        operands
    }

    pub unsafe fn is_operand_sreg(&self, index: u32) -> bool {
        let xi = xed_decoded_inst_inst(&self.inst);
        if index >= xed_inst_noperands(xi) { return false; }
        let operand_name: xed_operand_enum_t = xed_operand_name(xed_inst_operand(xi, index));
        if !matches!(operand_name, XED_OPERAND_REG0 | XED_OPERAND_REG1 | XED_OPERAND_REG2 | XED_OPERAND_REG3 | XED_OPERAND_REG4 | XED_OPERAND_REG5 | XED_OPERAND_REG6 | XED_OPERAND_REG7) {
            return false;
        }
        let reg = xed_decoded_inst_get_reg(&self.inst, operand_name);
        matches!(reg, XED_REG_ES | XED_REG_CS | XED_REG_SS | XED_REG_DS | XED_REG_FS | XED_REG_GS)
    }

    unsafe fn xed_reg_to_opreg(reg: xed_reg_enum_t) -> InstrOperandReg {
        let enclosing_gpreg = match xed_get_largest_enclosing_register(reg) {
            XED_REG_RAX => Some(GpReg::Rax),
            XED_REG_RCX => Some(GpReg::Rcx),
            XED_REG_RDX => Some(GpReg::Rdx),
            XED_REG_RSI => Some(GpReg::Rsi),
            XED_REG_RDI => Some(GpReg::Rdi),
            XED_REG_RIP => Some(GpReg::Rip),
            XED_REG_RBP => Some(GpReg::Rbp),
            XED_REG_RBX => Some(GpReg::Rbx),
            XED_REG_RSP => Some(GpReg::Rsp),
            XED_REG_R8 => Some(GpReg::R8),
            XED_REG_R9 => Some(GpReg::R9),
            XED_REG_R10 => Some(GpReg::R10),
            XED_REG_R11 => Some(GpReg::R11),
            XED_REG_R12 => Some(GpReg::R12),
            XED_REG_R13 => Some(GpReg::R13),
            XED_REG_R14 => Some(GpReg::R14),
            XED_REG_R15 => Some(GpReg::R15),
            XED_REG_FSBASE => Some(GpReg::FsBase),
            XED_REG_GSBASE => Some(GpReg::GsBase),
            XED_REG_RFLAGS => Some(GpReg::RFlags),
            _ => None,
        };
        if let Some(gpreg) = enclosing_gpreg {
            let width = xed_get_register_width_bits64(reg) / 8;
            let offset = match reg {
                XED_REG_AH | XED_REG_CH | XED_REG_DH | XED_REG_BH => 1,
                _ => 0,
            };
            return InstrOperandReg::GpReg { reg: gpreg, width: width as u8, offset: offset as u8 };
        }

        match reg {
            XED_REG_MMX0 | XED_REG_ST0 => InstrOperandReg::X87Reg(X87Reg::Fpr(0)),
            XED_REG_MMX1 | XED_REG_ST1 => InstrOperandReg::X87Reg(X87Reg::Fpr(1)),
            XED_REG_MMX2 | XED_REG_ST2 => InstrOperandReg::X87Reg(X87Reg::Fpr(2)),
            XED_REG_MMX3 | XED_REG_ST3 => InstrOperandReg::X87Reg(X87Reg::Fpr(3)),
            XED_REG_MMX4 | XED_REG_ST4 => InstrOperandReg::X87Reg(X87Reg::Fpr(4)),
            XED_REG_MMX5 | XED_REG_ST5 => InstrOperandReg::X87Reg(X87Reg::Fpr(5)),
            XED_REG_MMX6 | XED_REG_ST6 => InstrOperandReg::X87Reg(X87Reg::Fpr(6)),
            XED_REG_MMX7 | XED_REG_ST7 => InstrOperandReg::X87Reg(X87Reg::Fpr(7)),

            XED_REG_XMM0 => InstrOperandReg::XmmReg(XmmReg::Reg(0)),
            XED_REG_XMM1 => InstrOperandReg::XmmReg(XmmReg::Reg(1)),
            XED_REG_XMM2 => InstrOperandReg::XmmReg(XmmReg::Reg(2)),
            XED_REG_XMM3 => InstrOperandReg::XmmReg(XmmReg::Reg(3)),
            XED_REG_XMM4 => InstrOperandReg::XmmReg(XmmReg::Reg(4)),
            XED_REG_XMM5 => InstrOperandReg::XmmReg(XmmReg::Reg(5)),
            XED_REG_XMM6 => InstrOperandReg::XmmReg(XmmReg::Reg(6)),
            XED_REG_XMM7 => InstrOperandReg::XmmReg(XmmReg::Reg(7)),
            XED_REG_XMM8 => InstrOperandReg::XmmReg(XmmReg::Reg(8)),
            XED_REG_XMM9 => InstrOperandReg::XmmReg(XmmReg::Reg(9)),
            XED_REG_XMM10 => InstrOperandReg::XmmReg(XmmReg::Reg(10)),
            XED_REG_XMM11 => InstrOperandReg::XmmReg(XmmReg::Reg(11)),
            XED_REG_XMM12 => InstrOperandReg::XmmReg(XmmReg::Reg(12)),
            XED_REG_XMM13 => InstrOperandReg::XmmReg(XmmReg::Reg(13)),
            XED_REG_XMM14 => InstrOperandReg::XmmReg(XmmReg::Reg(14)),
            XED_REG_XMM15 => InstrOperandReg::XmmReg(XmmReg::Reg(15)),

            XED_REG_ES => InstrOperandReg::SReg("ES"),
            XED_REG_CS => InstrOperandReg::SReg("CS"),
            XED_REG_SS => InstrOperandReg::SReg("SS"),
            XED_REG_DS => InstrOperandReg::SReg("DS"),
            XED_REG_FS => InstrOperandReg::SReg("FS"),
            XED_REG_GS => InstrOperandReg::SReg("GS"),

            XED_REG_STACKPUSH => InstrOperandReg::StackPush,
            XED_REG_X87CONTROL => InstrOperandReg::X87Control,
            XED_REG_X87STATUS => InstrOperandReg::X87Status,
            XED_REG_X87TAG => InstrOperandReg::X87Reg(X87Reg::TagWord),

            XED_REG_CR0 => InstrOperandReg::ControlReg(0),
            XED_REG_CR1 => InstrOperandReg::ControlReg(1),
            XED_REG_CR2 => InstrOperandReg::ControlReg(2),
            XED_REG_CR3 => InstrOperandReg::ControlReg(3),
            XED_REG_CR4 => InstrOperandReg::ControlReg(4),
            XED_REG_CR5 => InstrOperandReg::ControlReg(5),
            XED_REG_CR6 => InstrOperandReg::ControlReg(6),
            XED_REG_CR7 => InstrOperandReg::ControlReg(7),
            XED_REG_CR8 => InstrOperandReg::ControlReg(8),
            XED_REG_CR9 => InstrOperandReg::ControlReg(9),
            XED_REG_CR10 => InstrOperandReg::ControlReg(10),
            XED_REG_CR11 => InstrOperandReg::ControlReg(11),
            XED_REG_CR12 => InstrOperandReg::ControlReg(12),
            XED_REG_CR13 => InstrOperandReg::ControlReg(13),
            XED_REG_CR14 => InstrOperandReg::ControlReg(14),
            XED_REG_CR15 => InstrOperandReg::ControlReg(15),

            _ => {
                error!("XED register {:?} not mapped to OpReg", reg);
                InstrOperandReg::Unk
            }
        }
    }
}
