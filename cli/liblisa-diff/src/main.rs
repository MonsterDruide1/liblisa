use std::{fs::File, io::BufReader, io::BufWriter};

use liblisa::Instruction;
use liblisa::arch::{Arch, x64::{X64Arch, GpReg}, CpuState};
use liblisa::encoding::{Encoding, dataflows::{AccessKind, AddressComputation, Dest, Inputs, MemoryAccess, MemoryAccesses, Size, Source}};
use liblisa::oracle::{Oracle, OracleError, OracleSource};
use liblisa::semantics::default::computation::SynthesizedComputation;
use liblisa::state::{Addr, Permissions, random::StateGen};
use liblisa_ghidra_x64_observer::GhidraOracle;
use liblisa_x64_observer::{VmOracle, VmOracleSource};
use liblisa_enc::AccessAnalysisError;
use rand::{Rng, SeedableRng};
use rand_xoshiro::Xoshiro256PlusPlus;

use crate::diff_oracle::FindDiffOracle;

pub mod diff_oracle;

fn run_instr(
    instr: &Instruction,
    num_states: usize,
    o: &mut FindDiffOracle<GhidraOracle, VmOracle>,
    rng: &mut impl rand::Rng
) -> Result<(), AccessAnalysisError<X64Arch>> {
    println!("Running instruction {:?}", instr);
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
    let mappable = o.mappable_area();
    let state_gen = StateGen::new(&accesses, &mappable)?;

    let mut ok = 0;
    let mut err = 0;
    while ok < num_states {
        if err > num_states*3 {
            return Err(AccessAnalysisError::InstructionKeepsFaulting);
        }
        let mut before = state_gen.randomize_new(rng)?;
        loop {
            let after = o.observe(&before);
            match after {
                Err(OracleError::MemoryAccess(addr)) => {
                    if addr.page::<X64Arch>() == Addr::new(CpuState::<X64Arch>::gpreg(before.cpu(), GpReg::Rip)).page() {
                        // cannot be mapped to the same page => start over with new state
                        before = state_gen.randomize_new(rng)?;
                        continue;
                    }
                    let mem = before.memory_mut();
                    let mut memory = std::mem::take(&mut mem.data).into_vec();
                    memory.push((addr, Permissions::ReadWrite, vec![0u8; 1]));
                    mem.data = memory.into_boxed_slice();
                }
                Err(OracleError::ApiError(e)) if e.contains("Ghidra emulator called a custom pcode op") => {
                    return Err(AccessAnalysisError::OracleError(OracleError::ApiError(e)));
                }
                Ok(_) => {
                    ok += 1;
                    break;
                }
                Err(_) => {
                    err += 1;
                    break;
                }
            }
        }
    }

    println!("Ran {} states for instruction {:?}", num_states, instr);
    Ok(())
}

pub fn main() {
    env_logger::init();

    let mut o = FindDiffOracle::new(
        GhidraOracle::new(),
        VmOracleSource::new(None, 1).start().into_iter().next().unwrap(),
    );
    let mut rng = Xoshiro256PlusPlus::seed_from_u64(rand::thread_rng().r#gen());

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
            let result = run_instr(&instr, num_states_per_instr, &mut o, &mut rng);
            match result {
                Ok(_) => {}
                Err(AccessAnalysisError::OracleError(e)) => {
                    println!("Oracle error: {}", e);
                }
                Err(e) => {
                    println!("Unexpected error: {}", e);
                }
            }
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
            let result = run_instr(&instr, num_states_per_instr, &mut o, &mut rng);
            match result {
                Ok(_) => {}
                Err(AccessAnalysisError::OracleError(e)) => {
                    println!("Oracle error: {}", e);
                }
                Err(e) => {
                    println!("Unexpected error: {}", e);
                }
            }
        }

        println!("Differences found: {}", o.diffs.len());
        println!("Differences: {:#?}", o.diffs.iter().take(10).map(|d| &d.diff_types).collect::<Vec<_>>());
        o.diffs.clear();
    }
}
