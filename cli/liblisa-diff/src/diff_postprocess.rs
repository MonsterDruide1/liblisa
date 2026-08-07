use crate::diff_types::{Diff, DiffResult};
use crate::state_diff::{Difference, DifferenceType, OkMismatch};
use liblisa::arch::{CpuState, x64::{GpReg, X64Arch, X64Flag}};
use liblisa::state::SystemState;
use thiserror::Error;
use xed_sys::*;

#[derive(Debug)]
pub enum ExplainedMismatch {
    UndefinedFlag(String, X64Flag),  // (instruction, flag)
    AfNotImplemented,
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
        }
    }
    pub fn name(&self) -> String {
        match self {
            ExplainedMismatch::UndefinedFlag(_, _) => "UndefinedFlag".to_string(),
            ExplainedMismatch::AfNotImplemented => "AfNotImplemented".to_string(),
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
                    // NOTE: one instruction might have multiple mismatches, so multiple entries could end up in `explained`!
                    // if one mismatch is unexplainable, abort checking the remaining mismatches to avoid duplicates in `unexplained`.
                    for mismatch in mismatches {
                        if let Some(explanation) = try_explain_mismatch(mismatch, &diff.example_before) {
                            explained.push(explanation);
                        } else {
                            unexplained.push(build_unexplained(i, j, &diff));
                            break;
                        }
                    }
                }
                _ => {
                    unexplained.push(build_unexplained(i, j, &diff));
                }
            }
        }
    }

    (explained, unexplained)
}

unsafe fn build_unexplained(item_index: usize, diff_index: usize, diff: &Difference) -> UnexplainedMismatch {
    let instr = get_instruction(&diff.example_before).unwrap_or(&[]);
    let xed = XedInterface::new(instr).expect("failed to get xed interface");
    let iclass = xed.get_iclass();
    UnexplainedMismatch {
        item_index,
        diff_index,
        diff_type: diff.diff_type.clone(),
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
        _ => None,
    }
}

/*pub unsafe fn postprocess_diff(item_index: usize, diff_index: usize, diff: &Difference) -> Result<(), XedError> {
    let pc = CpuState::<X64Arch>::gpreg(diff.example_before.cpu(), GpReg::Rip);
    let instruction = diff.example_before.memory().iter().find_map(|(addr, _, data)| {
        let offset = pc.checked_sub(addr.as_u64())?;
        if (offset as usize) < data.len() {
            Some(&data[offset as usize..])
        } else {
            None
        }
    }).unwrap_or(&[]);

    let xed = XedInterface::new(instruction)?;

    let OkOk(mismatches) = &diff.diff_type else {
        return Ok(());
    };

    let iclass = xed.get_iclass();
    println!("[{}-{}] = {:?} is {:?}", item_index, diff_index, instruction, iclass);

    let rflags_info = xed_decoded_inst_get_rflags_info(xedd.as_ptr());
    println!("[{}-{}] = {:?} is {:?}, rflags info: {:?}", i, j, instruction, iclass_str, rflags_info);
    let undef_flags = xed_simple_flag_get_undefined_flag_set(rflags_info);
    println!("[{}-{}] = {:?} is {:?}, undefined flags: {:?}", i, j, instruction, iclass_str, undef_flags);
    let buf = &mut [0i8; 500];
    xed_flag_set_print(undef_flags, buf.as_mut_ptr(), buf.len() as i32);
    println!("Done, attempting to print");
    println!("[{}-{}] = {:?} is {:?}, undefined flags: {}", i, j, instruction, iclass_str, std::ffi::CStr::from_ptr(buf.as_ptr()).to_string_lossy());

    Ok(())
}*/

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
}
