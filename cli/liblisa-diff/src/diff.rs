use liblisa_ghidra_x64_observer::GhidraOracle;
use liblisa_x64_observer::VmOracleSource;
use log::{debug, error, info, trace};
use rand::{Rng, SeedableRng};
use rand_xoshiro::Xoshiro256PlusPlus;

use liblisa::Instruction;
use liblisa::arch::{Arch, CpuState, x64::{GpReg, X64Arch}};
use liblisa::encoding::dataflows::{AccessKind, AddressComputation, Dest, Inputs, MemoryAccess, MemoryAccesses, Size, Source};
use liblisa::oracle::{Oracle, OracleError, OracleSource};
use liblisa::state::{Addr, Page, Permissions, SystemState, random::{StateGen, randomized_bytes}};

use crate::dummy_oracle_source::DoubleCheckedMappableArea;
use crate::state_diff::{self, Difference, DifferenceType};
use crate::diff_types::{DiffError, DiffThreadState};

use std::fs::File;

const MAX_MEMORY_ACCESS_OFFSET: u64 = 32;
const MAX_DIFFS_TO_KEEP: usize = 123;
const UNALIGNED_ACCESS_MAX_RETRIES: usize = 10;

fn translate_ghidra_error(e: &OracleError) -> Option<DiffError> {
    let OracleError::ApiError(e) = e else {
        return None;
    };
    if e.contains("Ghidra emulator called a custom pcode op") {
        Some(DiffError::GhidraCustomPcodeOp)
    } else if e.contains("Ghidra emulator reported varnode too large") {
        Some(DiffError::GhidraVarnodeTooLarge)
    } else {
        None
    }
}

fn try_add_memory_mapping(state: &mut SystemState<X64Arch>, addr: Addr, rng: &mut Xoshiro256PlusPlus) -> bool {
    if addr.page::<X64Arch>() == Addr::new(CpuState::<X64Arch>::gpreg(state.cpu(), GpReg::Rip)).page() {
        // cannot be mapped to the same page => start over with new state
        return false;
    }
    let mem = state.memory_mut();
    let mut memory = std::mem::take(&mut mem.data).into_vec();

    let addr_minus = addr.as_u64().saturating_sub(MAX_MEMORY_ACCESS_OFFSET);
    let start = addr_minus.max(addr.page::<X64Arch>().start_addr().as_u64());
    let addr = Addr::new(start);

    let addr_plus = addr.as_u64().saturating_add(MAX_MEMORY_ACCESS_OFFSET);
    let end = addr_plus.min(addr.page::<X64Arch>().last_address_of_page().as_u64());
    let size = end.checked_sub(start).unwrap();

    memory.push((addr, Permissions::ReadWrite, randomized_bytes(rng, size as usize)));
    mem.data = memory.into_boxed_slice();
    true
}

fn try_report_diff(diff: DifferenceType, before: &SystemState<X64Arch>, state: &mut DiffThreadState) -> bool {
    if let DifferenceType::ErrErr(e1, e2) = &diff {
        match (e1, e2) {
            (OracleError::MemoryAccess(addr1), OracleError::MemoryAccess(addr2)) => {
                if addr1.distance_between(*addr2) <= MAX_MEMORY_ACCESS_OFFSET {
                    // if the two memory accesses are close to each other, do not report it
                    // might happen because Ghidra optimizes loads, while CPU loads larger block
                    return false;
                }
            }
            _ => {}
        }
    }

    // if diff has already been reported, do not report again
    if state.diffs.iter().any(|d| d.diff_type.contains(&diff)) {
        return false;
    }

    debug!("Found diff: {}, adding to existing list:", diff);
    for d in &state.diffs {
        debug!("  {:?}", d.diff_type);
    }
    debug!("  {:?}", before);

    if state.diffs.len() > MAX_DIFFS_TO_KEEP {
        debug!("  ... (truncated, {} diffs total)", state.diffs.len());
        return true;
    }

    // seems good, delete smaller existing diffs and report this one
    state.diffs.retain(|d| !diff.contains(&d.diff_type));
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
) -> Result<bool, DiffError> {
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
    
    let mut unaligned_access_counter = 0;
    let mut before = state_gen.randomize_new(&mut state.rng)?;
    loop {
        let r1 = state.o1.observe(&before);
        let r2 = state.o2.observe(&before);

        // special case: Ghidra might throw custom errors indicating that emulation doesn't behave properly
        // => translate to `DiffError` and abort early
        if let Err(e) = &r1 {
            if let Some(diff_error) = translate_ghidra_error(e) {
                info!("Ghidra threw custom error, aborting early: {:?} due to {:?}", diff_error, e);
                return Err(diff_error);
            }
        }

        // special case: if Ghidra is fine, but CPU had MemoryAccess error, *and* the address
        // is directly next to an existing mapping, it's probably because Ghidra optimizes loads,
        // while the CPU loads larger blocks => map the additional page and try again
        if let (Ok(_), Err(OracleError::MemoryAccess(addr))) = (&r1, &r2) {
            let next_to_mapped = before.memory().iter().any(|(mapped_addr, _, _)| {
                let page: Page<X64Arch> = mapped_addr.page();
                addr.distance_between(page.start_addr()) <= MAX_MEMORY_ACCESS_OFFSET || addr.distance_between(page.last_address_of_page()) <= MAX_MEMORY_ACCESS_OFFSET
            });
            if next_to_mapped {
                debug!("CPU threw MemoryAccess with address next to existing mapping, while Ghidra was fine: {:?}, trying to add mapping and try again", addr);
                if !try_add_memory_mapping(&mut before, *addr, &mut state.rng) {
                    debug!("CPU threw MemoryAccess with address next to existing mapping, while Ghidra was fine: {:?}, but could not add mapping, randomizing new state and trying again", addr);
                    before = state_gen.randomize_new(&mut state.rng)?;
                }
                continue;
            }
        }

        // special case: if CPU throws General Fault with address that is not 16-byte aligned
        // and Ghidra reports MemoryAccess, it's because Ghidra doesn't handle unaligned accesses properly
        // => randomize new state and try again
        if let (Err(OracleError::MemoryAccess(addr)), Err(OracleError::GeneralFault)) = (&r1, &r2) {
            if addr.as_u64() % 16 != 0 {
                unaligned_access_counter += 1;
                if unaligned_access_counter > UNALIGNED_ACCESS_MAX_RETRIES {
                    info!("Instruction keeps causing unaligned access ({} retries), aborting: {:?}", unaligned_access_counter, instr);
                    return Err(DiffError::UnalignedAccessKeepsFaulting);
                }
                before = state_gen.randomize_new(&mut state.rng)?;
                continue;
            }
        }

        let result = state_diff::compare(&r1, &r2);
        if let Some(result) = result {
            try_report_diff(result, &before, state);
        }

        // if page fault occurred, try adding mapping and try again
        // if mapping cannot be added, randomize new state and try again
        if let Err(OracleError::MemoryAccess(addr)) = r1 {
            if !try_add_memory_mapping(&mut before, addr, &mut state.rng) {
                before = state_gen.randomize_new(&mut state.rng)?;
            }
            continue;
        }
        else if let Err(OracleError::MemoryAccess(addr)) = r2 {
            if !try_add_memory_mapping(&mut before, addr, &mut state.rng) {
                before = state_gen.randomize_new(&mut state.rng)?;
            }
            continue;
        }
        else {
            // neither of them faulted, and we already reported the potential diff => done
            trace!("Instruction executed on both oracles without page fault: {:?}", instr);
            trace!("  Ghidra result: {:?}", r1);
            trace!("  VM result: {:?}", r2);

            // if both agree that the instruction is invalid, throw harder error to abort early
            if let (Err(OracleError::InvalidInstruction), Err(OracleError::InvalidInstruction)) = (&r1, &r2) {
                return Err(DiffError::InvalidInstruction);
            }

            return Ok(r1.is_ok() && r2.is_ok())
        }
    }
}

pub fn run_instr(
    instr: &Instruction,
    num_states: usize,
    state: &mut DiffThreadState
) -> Result<(), DiffError> {
    let mut ok = 0;
    let mut err = 0;
    while ok < num_states {
        if err > num_states*3 {
            error!("Instruction keeps faulting ({} ok, {} err), aborting: {:?}", ok, err, instr);
            return Err(DiffError::InstructionKeepsFaulting);
        }
        if run_instr_single(instr, state)? {
            ok += 1;
        } else {
            err += 1;
        }
    }

    Ok(())
}

pub fn create_state() -> DiffThreadState {
    let o1 = GhidraOracle::new();
    let o2 = VmOracleSource::new(None, 1).start().into_iter().next().unwrap();
    let mappable: DoubleCheckedMappableArea<liblisa_ghidra_x64_observer::GhidraMappableArea, liblisa_x64_observer::VmMappableArea> = DoubleCheckedMappableArea(o1.mappable_area(), o2.mappable_area());
    DiffThreadState {
        o1,
        o2,
        mappable,
        diffs: vec![],
        rng: Xoshiro256PlusPlus::seed_from_u64(rand::thread_rng().r#gen())
    }
}
