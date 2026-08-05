use liblisa::{Instruction, arch::{Arch, CpuState, x64::{GpReg, X64Arch}}, encoding::dataflows::{AccessKind, AddressComputation, Dest, Inputs, MemoryAccess, MemoryAccesses, Size, Source}, oracle::{Oracle, OracleError}, state::{Addr, Permissions, SystemState, random::{RandomizationError, StateGen}}};
use liblisa_enc::AccessAnalysisError;

use crate::state_diff::{self, Difference, DifferenceType};
use crate::diff_types::DiffThreadState;


fn is_ghidra_pcode_error(e: &OracleError) -> bool {
    match e {
        OracleError::ApiError(e) => e.contains("Ghidra emulator called a custom pcode op"),
        _ => false,
    }
}

fn try_add_memory_mapping(state: &mut SystemState<X64Arch>, addr: Addr) -> bool {
    if addr.page::<X64Arch>() == Addr::new(CpuState::<X64Arch>::gpreg(state.cpu(), GpReg::Rip)).page() {
        // cannot be mapped to the same page => start over with new state
        return false;
    }
    let mem = state.memory_mut();
    let mut memory = std::mem::take(&mut mem.data).into_vec();
    memory.push((addr, Permissions::ReadWrite, vec![0u8; 1]));
    mem.data = memory.into_boxed_slice();
    true
}

fn try_report_diff(diff: DifferenceType, before: &SystemState<X64Arch>, state: &mut DiffThreadState) -> bool {
    // if diff has already been reported, do not report again
    if state.diffs.iter().any(|d| d.diff_type.contains(&diff)) {
        return false;
    }
    
    // if diff relates to Ghidra's custom pcode op, do not report it
    if let DifferenceType::ErrOk(e) = &diff {
        if is_ghidra_pcode_error(e) {
            return false;
        }
    }
    if let DifferenceType::ErrErr(e, _) = &diff {
        if is_ghidra_pcode_error(e) {
            return false;
        }
    }

    // seems good, report new diff now
    state.diffs.push(Difference {
        diff_type: diff,
        example_before: before.clone(),
    });
    true
}

// returns whether the instruction was executed successfully (i.e. no page fault occurred) on both oracles
fn run_instr_single(
    instr: &Instruction,
    state: &mut DiffThreadState,
) -> Result<bool, RandomizationError> {
    let accesses: MemoryAccesses<X64Arch> = MemoryAccesses {
        instr: *instr,
        memory: vec![MemoryAccess {
            inputs: Inputs::sorted(vec![Source::Dest(Dest::Reg(X64Arch::reg(X64Arch::PC), Size::qword()))]),
            kind: AccessKind::Executable,
            size: instr.byte_len() as u64..instr.byte_len() as u64,
            calculation: AddressComputation::unscaled_sum(1),
            alignment: 1,
        }],
        use_trap_flag: true,
    };
    let map = state.mappable.clone();
    let state_gen = StateGen::new(&accesses, &map)?;
    
    let mut before = state_gen.randomize_new(&mut state.rng)?;
    loop {
        let r1 = state.o1.observe(&before);
        let r2 = state.o2.observe(&before);

        let result = state_diff::compare(&r1, &r2);
        if let Some(result) = result {
            try_report_diff(result, &before, state);
        }

        // if page fault occurred, try adding mapping and try again
        // if mapping cannot be added, randomize new state and try again
        if let Err(OracleError::MemoryAccess(addr)) = r1 {
            if !try_add_memory_mapping(&mut before, addr) {
                before = state_gen.randomize_new(&mut state.rng)?;
            }
            continue;
        }
        else if let Err(OracleError::MemoryAccess(addr)) = r2 {
            if !try_add_memory_mapping(&mut before, addr) {
                before = state_gen.randomize_new(&mut state.rng)?;
            }
            continue;
        }
        else {
            // neither of them faulted, and we already reported the potential diff => done
            return Ok(
                (r1.is_ok() || r1.is_err_and(|e| is_ghidra_pcode_error(&e)))
                && (r2.is_ok() || r2.is_err_and(|e| is_ghidra_pcode_error(&e)))
            );
        }
    }
}

pub fn run_instr(
    instr: &Instruction,
    num_states: usize,
    state: &mut DiffThreadState
) -> Result<(), AccessAnalysisError<X64Arch>> {
    let mut ok = 0;
    let mut err = 0;
    while ok < num_states {
        if err > num_states*3 {
            return Err(AccessAnalysisError::InstructionKeepsFaulting);
        }
        if run_instr_single(instr, state)? {
            ok += 1;
        } else {
            err += 1;
        }
    }

    Ok(())
}
