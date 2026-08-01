use std::{fs::File, io::BufReader, io::BufWriter};

use liblisa::Instruction;
use liblisa::arch::{Arch, x64::{X64Arch, GpReg}, CpuState};
use liblisa::encoding::{Encoding, dataflows::{AccessKind, AddressComputation, Dest, Inputs, MemoryAccess, MemoryAccesses, Size, Source}};
use liblisa::oracle::{MappableArea, Oracle, OracleError, OracleSource};
use liblisa::semantics::default::computation::SynthesizedComputation;
use liblisa::state::SystemState;
use liblisa::state::random::RandomizationError;
use liblisa::state::{Addr, Permissions, random::StateGen};
use liblisa_ghidra_x64_observer::GhidraOracle;
use liblisa_x64_observer::{VmOracle, VmOracleSource};
use liblisa_enc::AccessAnalysisError;
use rand::{Rng, SeedableRng};
use rand_xoshiro::Xoshiro256PlusPlus;

use crate::state_diff::{Difference, DifferenceType};

pub mod state_diff;

#[derive(Clone, Debug)]
pub struct DoubleCheckedMappableArea<A: MappableArea, B: MappableArea>(A, B);

impl<A: MappableArea, B: MappableArea> MappableArea for DoubleCheckedMappableArea<A, B> {
    fn can_map(&self, addr: Addr) -> bool {
        self.0.can_map(addr) && self.1.can_map(addr)
    }
}

struct DiffState {
    pub o1: GhidraOracle,
    pub o2: VmOracle,
    pub mappable: DoubleCheckedMappableArea<<GhidraOracle as Oracle<X64Arch>>::MappableArea, <VmOracle as Oracle<X64Arch>>::MappableArea>,
    pub diffs: Vec<Difference>,
    pub rng: Xoshiro256PlusPlus,
}

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

fn try_report_diff(diff: DifferenceType, before: &SystemState<X64Arch>, state: &mut DiffState) -> bool {
    // if diff has already been reported, do not report again
    if state.diffs.iter().any(|d| d.diff_type == diff) {
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
    state: &mut DiffState,
) -> Result<bool, RandomizationError> {
    // TODO: use static instances of state_gen depending on instruction length, to avoid re-running ctor every time
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

fn run_instr(
    instr: &Instruction,
    num_states: usize,
    state: &mut DiffState
) -> Result<(), AccessAnalysisError<X64Arch>> {
    println!("Running instruction {:?}", instr);

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

    println!("Ran {} states for instruction {:?}", num_states, instr);
    Ok(())
}

pub fn main() -> Result<(), AccessAnalysisError<X64Arch>> {
    env_logger::init();

    let o1 = GhidraOracle::new();
    let o2 = VmOracleSource::new(None, 1).start().into_iter().next().unwrap();
    let mappable = DoubleCheckedMappableArea(o1.mappable_area(), o2.mappable_area());
    let mut state = DiffState {
        o1,
        o2,
        mappable,
        diffs: Vec::new(),
        rng: Xoshiro256PlusPlus::seed_from_u64(rand::thread_rng().r#gen()),
    };

    let encodings = "semantics/small.json";
    let num_instrs_per_encoding = 100;
    let num_states_per_instr = 2500;

    println!("Reading encoding...");
    let encodings: Vec<Encoding<X64Arch, SynthesizedComputation>> =
        serde_json::from_reader(BufReader::new(File::open(&encodings).unwrap())).unwrap();
    println!("Read {} encodings.", encodings.len());

    serde_json::to_writer(
        BufWriter::new(File::create("semantics/small.json").unwrap()),
        &encodings.iter().take(500).collect::<Vec<_>>()
    ).unwrap();

    for e in encodings.into_iter().take(5) {
        // 1. run with best_instr
        if let Some(instr) = e.best_instr() {
            run_instr(&instr, num_states_per_instr, &mut state)?;
        }

        // 2. estimate number of instructions within encoding
        let num_instrs = 2_usize.pow(e.num_wildcard_bits() as u32);

        // 3. if smaller than threshold, run with all instructions,
        //    otherwise run with a random sample of instructions
        let iterator = if num_instrs <= num_instrs_per_encoding {
            e.iter_instrs(&[None; 10000], true).collect::<Vec<_>>()
        } else {
            e.random_instrs(&[None; 10000], &mut rand::thread_rng()).take(num_instrs_per_encoding).collect::<Vec<_>>()
        };
        for instr in iterator {
            run_instr(&instr, num_states_per_instr, &mut state)?;
        }

        println!("Differences found: {}", state.diffs.len());
        println!("Differences: {:#?}", state.diffs.iter().take(10).map(|d| &d.diff_type).collect::<Vec<_>>());
        state.diffs.clear();
    }

    Ok(())
}
