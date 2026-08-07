use crate::diff_types::{Diff, DiffResult};
use crate::state_diff::{DifferenceType, OkMismatch};
use liblisa::arch::{CpuState, x64::{GpReg, X64Arch, X64Flag, X64Reg, X87Reg}};
use liblisa::state::SystemState;
use thiserror::Error;
use xed_sys::*;

#[derive(Debug)]
pub enum ExplainedMismatch {
    /// flag is undefined as per intel manual/XED, CPUs/Ghidra might implement it differently
    UndefinedFlag(String, X64Flag),  // (instruction, flag)
    /// AF flag is not handled in Ghidra properly
    AfNotImplemented,
    /// using MMX instructions resets X87 stack (top-of-stack and tag-word), which is not done in Ghidra
    X87ResetOnMMX,
    /// in Ghidra's implementation for `PMINSW` and similar functions: `local srcCopy:8 = mmxreg2_m64;`
    /// => reuses lower 8/16 bits for entire calculation, not just the lower 8/16 bits of the result
    /// example: 0fde17 -r FTW=ff -r RDI=12345678 -m 12345678=20 -r mm2=00
    ///   CPU: mm2=0x00000000000000000020 ; Ghidra: mm2=0x00002020202020202020
    /// TODO: more research on why this actually happens?
    PMaxMinSrcCopy,
}

impl ExplainedMismatch {
    pub fn description(&self) -> String {
        match self {
            ExplainedMismatch::UndefinedFlag(iclass, flag) => {
                format!("Undefined flag {:?} in instruction {}", flag, iclass)
            }
            ExplainedMismatch::AfNotImplemented => {
                "AF flag mismatch is not implemented".to_string()
            }
            ExplainedMismatch::X87ResetOnMMX => {
                "X87 stack reset on MMX instruction is not implemented".to_string()
            }
            ExplainedMismatch::PMaxMinSrcCopy => {
                "Ghidra's implementation of PMAX/PMIN instructions reuses lower bits of source for entire calculation".to_string()
            }
        }
    }
    pub fn name(&self) -> String {
        match self {
            ExplainedMismatch::UndefinedFlag(_, _) => "UndefinedFlag".to_string(),
            ExplainedMismatch::AfNotImplemented => "AfNotImplemented".to_string(),
            ExplainedMismatch::X87ResetOnMMX => "X87ResetOnMMX".to_string(),
            ExplainedMismatch::PMaxMinSrcCopy => "PMaxMinSrcCopy".to_string(),
        }
    }
}

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

unsafe fn get_instruction(state: &SystemState<X64Arch>) -> Option<&[u8]> {
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
        X87RegMismatch(reg, ghidra, vm) => {
            let xed = get_xed_interface(state).expect("failed to get xed interface");
            let iclass = xed.get_iclass();
            if ["PMAXSW", "PMAXUB", "PMINSW", "PMINUB"].contains(&iclass.as_str()) {
                if xed.get_operands_mm().get(0) == Some(&X64Reg::X87(*reg)) {
                    return Some(ExplainedMismatch::PMaxMinSrcCopy);
                }
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
    pub unsafe fn get_operands_mm(&self) -> Vec<X64Reg> {
        let xi = xed_decoded_inst_inst(&self.inst);
        let mut operands = Vec::new();
        for i in 0..xed_inst_noperands(xi) {
            let operand_name = xed_operand_name(xed_inst_operand(xi, i));
            let reg = match xed_decoded_inst_get_reg(&self.inst, operand_name) {
                XED_REG_MMX0 => X64Reg::X87(X87Reg::Fpr(0)),
                XED_REG_MMX1 => X64Reg::X87(X87Reg::Fpr(1)),
                XED_REG_MMX2 => X64Reg::X87(X87Reg::Fpr(2)),
                XED_REG_MMX3 => X64Reg::X87(X87Reg::Fpr(3)),
                XED_REG_MMX4 => X64Reg::X87(X87Reg::Fpr(4)),
                XED_REG_MMX5 => X64Reg::X87(X87Reg::Fpr(5)),
                XED_REG_MMX6 => X64Reg::X87(X87Reg::Fpr(6)),
                XED_REG_MMX7 => X64Reg::X87(X87Reg::Fpr(7)),
                _ => continue,
            };
            operands.push(reg);
        }
        operands
    }
}
