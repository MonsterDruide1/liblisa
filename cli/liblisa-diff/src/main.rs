use std::{fs::File, io::BufReader};

use liblisa::{Instruction, arch::{Arch, x64::X64Arch}, encoding::{Encoding, dataflows::{AccessKind, AddressComputation, Dest, Inputs, MemoryAccess, MemoryAccesses, Size, Source}}, oracle::{Oracle, OracleError, OracleSource}, semantics::default::computation::SynthesizedComputation, state::{Permissions, random::StateGen}};
use liblisa_ghidra_x64_observer::GhidraOracle;
use liblisa_x64_observer::{VmOracle, VmOracleSource};
use liblisa_enc::{AccessAnalysisError, MemoryAccessAnalysis};
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

    let mut states = 0;
    while states < num_states {
        let mut before = state_gen.randomize_new(rng)?;
        loop {
            let after = o.observe(&before);
            match after {
                Ok(_) => {
                    states += 1;
                    break;
                }
                Err(OracleError::MemoryAccess(addr)) => {
                    let mem = before.memory_mut();
                    let mut memory = std::mem::take(&mut mem.data).into_vec();
                    memory.push((addr, Permissions::ReadWrite, vec![0u8; 4]));
                    mem.data = memory.into_boxed_slice();
                }
                Err(e) => {
                    return Err(AccessAnalysisError::OracleError(e));
                }
            }
        }
    }

    Ok(())
}

pub fn main() {
    env_logger::init();

    let mut o = FindDiffOracle::new(
        GhidraOracle::new(),
        VmOracleSource::new(None, 1).start().into_iter().next().unwrap(),
    );
    let mut rng = Xoshiro256PlusPlus::seed_from_u64(rand::thread_rng().r#gen());

    let encodings = "semantics/amd-7700x.json";
    let num_instrs_per_encoding = 100;
    let num_states_per_instr = 2500;

    let encodings: Vec<Encoding<X64Arch, SynthesizedComputation>> =
        serde_json::from_reader(BufReader::new(File::open(&encodings).unwrap())).unwrap();
    for e in encodings.into_iter().take(5) {
        // 1. run with best_instr
        if let Some(instr) = e.best_instr() {
            let _ = MemoryAccessAnalysis::infer::<X64Arch, _>(&mut o, &instr);
        }

        // 2. estimate number of instructions within encoding
        let num_instrs = 2usize.pow(e.num_wildcard_bits() as u32);

        // 3. if smaller than threshold, run with all instructions,
        //    otherwise run with a random sample of instructions
        let iterator = if num_instrs <= num_instrs_per_encoding {
            e.iter_instrs(&[None; 10000], true).collect::<Vec<_>>()
        } else {
            e.random_instrs(&[None; 10000], &mut rand::thread_rng()).take(num_instrs_per_encoding).collect::<Vec<_>>()
        };
        for instr in iterator {
            run_instr(&instr, num_states_per_instr, &mut o, &mut rng).unwrap();
        }

        println!("Differences found: {}", o.diffs.len());
        println!("Differences: {:#?}", o.diffs.take(10).map(|d| d.diff_types).collect::<Vec<_>>());
        o.diffs.clear();
    }
}
