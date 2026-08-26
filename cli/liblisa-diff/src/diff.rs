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
use serde::{Deserialize, Serialize};

use crate::dummy_oracle_source::DoubleCheckedMappableArea;
use crate::state_diff::{self, Difference, DifferenceType};
use crate::diff_types::{DiffError, DiffThreadState};

const MAX_MEMORY_ACCESS_OFFSET: u64 = 32;
const MAX_DIFFS_TO_KEEP: usize = 123;
const UNALIGNED_ACCESS_MAX_RETRIES: usize = 16*10;  // 1 / 16 is aligned, boost chance by *10 to avoid false positives due to bad RNG
// runtime difference: 2s vs. 24s on a single instruction with 2500 states
// may only lead to false positives (= more mismatches reported), so is fine to enable
const MEM_ACCESS_SCAN_GHIDRA_ONLY: bool = true;

fn translate_ghidra_error(e: &OracleError) -> Option<DiffError> {
    let OracleError::ApiError(e) = e else {
        return None;
    };
    if e.contains("Ghidra emulator called a custom pcode op") {
        Some(DiffError::GhidraCustomPcodeOp)
    } else if e.contains("Ghidra emulator reported varnode too large") {
        Some(DiffError::GhidraVarnodeTooLarge)
    } else if e.contains("Ghidra emulator reported emulation unimplemented") {
        Some(DiffError::GhidraEmulationUnimplemented)
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
    let new_addr = Addr::new(start);

    let addr_plus = addr.as_u64().saturating_add(MAX_MEMORY_ACCESS_OFFSET);
    let end = addr_plus.min(addr.page::<X64Arch>().last_address_of_page().as_u64());
    let size = end.checked_sub(start).unwrap() + 1;

    memory.push((new_addr, Permissions::ReadWrite, randomized_bytes(rng, size as usize)));
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

enum RunResult {
    Ok,
    BothGP,
    KeepsUnaligned,
    Unknown,
}
// returns whether the instruction was executed successfully (i.e. no page fault occurred) on both oracles
fn run_instr_single(
    instr: &Instruction,
    state: &mut DiffThreadState,
) -> Result<RunResult, DiffError> {
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
        let mut r1 = state.o1.observe(&before);
        let mut r2 = state.o2.observe(&before);

        // if any of them complain about invalid instruction, abort immediately
        let invalid1 = r1.as_ref().is_err_and(|e| *e == OracleError::InvalidInstruction);
        let invalid2 = r2.as_ref().is_err_and(|e| *e == OracleError::InvalidInstruction);
        if invalid1 || invalid2 {
            debug!("Instruction is invalid on Ghidra={invalid1} or VM={invalid2}, aborting: {:?}", instr);
            return Err(DiffError::InvalidInstruction(invalid1, invalid2));
        }

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

        // special case: if CPU throws General Fault due to address that is not 16-byte aligned and Ghidra reports
        // - MemoryAccess with non-16-divisible address (=> unaligned access address),
        // - MemoryAccess on first byte of page directly after a mapped page (=> flows into next page),
        // - reports no failure at all (=> access is on already-mapped page)
        // it's because Ghidra doesn't handle unaligned accesses properly
        // => randomize new state and try again
        let is_unaligned_access = match (&r1, &r2) {
            (Err(OracleError::MemoryAccess(addr)), Err(OracleError::GeneralFault)) => {
                if addr.as_u64() % 16 != 0 {
                    // non-16-byte-aligned access address => unaligned access itself
                    true
                } else if addr.as_u64() == addr.page::<X64Arch>().start_addr().as_u64() {
                    // potentially first byte after mapped page with unaligned access
                    before.memory().iter().any(|(mapped_addr, _, _)| {
                        let page: Page<X64Arch> = mapped_addr.page();
                        page.last_address_of_page().as_u64() == addr.page::<X64Arch>().start_addr().as_u64().wrapping_sub(1)
                    })
                } else {
                    false
                }
            }
            (Ok(_), Err(OracleError::GeneralFault)) => {
                // Ghidra did not report any error, but CPU threw General Fault
                // we cannot do more precise checks here, but it's likely an unaligned access
                true
            }
            _ => false,
        };
        if is_unaligned_access {
            unaligned_access_counter += 1;
            if unaligned_access_counter > UNALIGNED_ACCESS_MAX_RETRIES {
                info!("Instruction keeps causing unaligned access ({} retries), aborting: {:?}", unaligned_access_counter, instr);
                return Ok(RunResult::KeepsUnaligned);
            }
            before = state_gen.randomize_new(&mut state.rng)?;
            continue;
        }

        // special case: page faults on CPU due to non-writable memory while Ghidra is fine might happen due to conditional write
        // if conditional writes may happen, CPU throws page faults eagerly, even if write is not actually performed.
        // While Intel does not specify this, AMD is explicit for CMPXCHG:
        // > If the compared operands were unequal, CMPXCHG writes the same value to the memory operand that was read.
        // https://www.sra.uni-hannover.de/Lehre/SS21/V_BSB/doc/amd64_manual_vol3.pdf
        // => try mapping as writable and try again, if mapping cannot be added, randomize new state and try again
        if let (Ok(_), Err(OracleError::MemoryAccess(addr))) = (&r1, &r2) {
            let is_writable = before.memory().iter().any(|(mapped_addr, perms, data)| {
                mapped_addr.into_area(data.len() as u64).contains(*addr) && *perms == Permissions::ReadWrite
            });
            if !is_writable {
                debug!("CPU threw MemoryAccess on non-writable memory, while Ghidra was fine: {:?}, trying to add mapping and try again", addr);
                if !try_add_memory_mapping(&mut before, *addr, &mut state.rng) {
                    debug!("CPU threw MemoryAccess on non-writable memory, while Ghidra was fine: {:?}, but could not add mapping, randomizing new state and trying again", addr);
                    before = state_gen.randomize_new(&mut state.rng)?;
                }
                continue;
            }
        }

        // if page fault occurred, try adding mapping and try again
        // if mapping cannot be added, randomize new state and try again
        if let Err(OracleError::MemoryAccess(addr)) = r1 {
            if let Some(result) = state_diff::compare(&r1, &r2) {
                try_report_diff(result, &before, state);
            }
            if !try_add_memory_mapping(&mut before, addr, &mut state.rng) {
                before = state_gen.randomize_new(&mut state.rng)?;
            }
            continue;
        }
        if let Err(OracleError::MemoryAccess(addr)) = r2 {
            if let Some(result) = state_diff::compare(&r1, &r2) {
                try_report_diff(result, &before, state);
            }
            if !try_add_memory_mapping(&mut before, addr, &mut state.rng) {
                before = state_gen.randomize_new(&mut state.rng)?;
            }
            continue;
        }

        // scan memory accesses and add new mappings for any that are not already mapped
        // might happen if accesses go to already-mapped page, but outside mapped range
        let mut any_new_mappings = false;
        let mut restart = false;
        loop {
            let mut need_more_mappings = false;

            let mut addrs = vec![];
            if r1.is_ok() {
                addrs.extend(state.o1.scan_memory_accesses(&before).expect("scan_memory_accesses should not fail if observe succeeded"));
            }
            if r2.is_ok() && (!MEM_ACCESS_SCAN_GHIDRA_ONLY || r1.is_err()) {
                addrs.extend(state.o2.scan_memory_accesses(&before).expect("scan_memory_accesses should not fail if observe succeeded"));
            }
            
            for addr in addrs {
                let is_mapped = before.memory().iter().any(|(mapped_addr, _, data)| {
                    mapped_addr.into_area(data.len() as u64).contains(addr)
                });
                if !is_mapped {
                    debug!("Adding mapping for memory access to {:x} that was not already mapped", addr.as_u64());
                    debug!("  before: {:?}", before);
                    if !try_add_memory_mapping(&mut before, addr, &mut state.rng) {
                        before = state_gen.randomize_new(&mut state.rng)?;
                        // do not continue adding more mapping, as new state has been generated
                        restart = true;
                        break;
                    }
                    // try_add_memory_mapping adds range, and accesses might contain duplicates, so just start over and re-scan
                    need_more_mappings = true;
                    any_new_mappings = true;
                }
            }
            // for restart: do not try collecting more mappings here, as new state must first be checked with MemoryAccess errors
            // if no new mappings were added, we can break out of the loop and continue with the instruction execution
            if restart || !need_more_mappings {
                break;
            }
        }
        if restart {
            continue;  // start over with the outer loop on the new state
        }
        if any_new_mappings {
            // done with adding mappings, re-execute state to get final result
            r1 = state.o1.observe(&before);
            r2 = state.o2.observe(&before);
        }
        

        let result = state_diff::compare(&r1, &r2);
        if let Some(result) = result {
            try_report_diff(result, &before, state);
        }

        
        // neither of them faulted, and we already reported the potential diff => done
        trace!("Instruction executed on both oracles without page fault: {:?}", instr);
        trace!("  Ghidra result: {:?}", r1);
        trace!("  VM result: {:?}", r2);

        if r1.is_ok() && r2.is_ok() {
            return Ok(RunResult::Ok);
        } else if r1 == Err(OracleError::GeneralFault) && r2 == Err(OracleError::GeneralFault) {
            return Ok(RunResult::BothGP);
        } else {
            error!("Instruction executed on both oracles, but one of them faulted: {:?}", instr);
            error!("  Ghidra result: {:?}", r1);
            error!("  VM result: {:?}", r2);
            return Ok(RunResult::Unknown);
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunResultCounts {
    pub ok: usize,
    pub both_gp: usize,  // might happen due to bad RNG with registers, but also due to hardcoded addresses
    pub keeps_unaligned: usize,  // might happen due to hardcoded, unaligned addresses
    pub unknown: usize,
}
pub fn run_instr(
    instr: &Instruction,
    num_states: usize,
    state: &mut DiffThreadState
) -> Result<RunResultCounts, DiffError> {
    let mut ok = 0;
    let mut gp = 0;
    let mut keeps_unaligned = 0;
    let mut unk = 0;
    for _ in 0..num_states {
        let result = run_instr_single(instr, state)?;
        match result {
            RunResult::Ok => {
                ok += 1;
            }
            RunResult::BothGP => {
                gp += 1;
            }
            RunResult::KeepsUnaligned => {
                keeps_unaligned += 1;
            }
            RunResult::Unknown => {
                unk += 1;
            }
        }
    }

    Ok(RunResultCounts { ok, both_gp: gp, keeps_unaligned, unknown: unk })
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
