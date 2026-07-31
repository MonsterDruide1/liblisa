use std::{fs::File, io::BufReader};

use clap::Parser;
use liblisa::{arch::x64::{PrefixScope, X64Arch}, encoding::Encoding, oracle::OracleSource, semantics::default::computation::SynthesizedComputation};
use liblisa_libcli::CliCommand;
use liblisa_ghidra_x64_observer::{GhidraOracleSource, GhidraOracle};
use log::trace;
use liblisa_x64_observer::{VmOracle, VmOracleSource};
use liblisa_enc::{DataflowAnalysis, MemoryAccessAnalysis};

use liblisa::oracle::Oracle;
use liblisa::state::Permissions;
use liblisa::state::Addr;
use liblisa::arch::x64::GpReg;
use liblisa::state::MemoryState;
use liblisa::arch::x64::X64State;
use liblisa::state::SystemState;

use crate::oracle::GhidraVerifyOracle;
use crate::diff_oracle::FindDiffOracle;

pub mod oracle;
pub mod diff_oracle;

pub struct GhidraVerifierOracleSource {}
impl GhidraVerifierOracleSource {
    pub fn new() -> Self {
        Self {}
    }
}
impl OracleSource for GhidraVerifierOracleSource {
    type Oracle = GhidraVerifyOracle<GhidraOracle, VmOracle>;

    fn start(&self) -> Vec<Self::Oracle> {
        vec![
            GhidraVerifyOracle::new(
                GhidraOracle::new(),
                VmOracleSource::new(None, 2).start().into_iter().next().unwrap(),
            ),
        ]
    }
}

pub fn main() {
    env_logger::init();

    let args = CliCommand::<X64Arch>::parse();
    trace!("Args: {args:#?}");
    /*{
        let mut o = GhidraVerifierOracleSource::new().start().into_iter().next().unwrap();
        let mut state = SystemState::<X64Arch> {
            cpu: Box::new(X64State::default()),
            memory: MemoryState::default(),
            contains_valid_addrs: true,
            use_trap_flag: false,
        };
        state.cpu_mut().regs[GpReg::Rip as usize] = 0x000000000006DFE4;
        state.cpu_mut().regs[GpReg::Rax as usize] = 0x00003FFFFFFE4E08;
        state.cpu_mut().regs[GpReg::Rcx as usize] = 0x993D6F583DB34B00;
        state.cpu_mut().regs[GpReg::RFlags as usize] = 0x0000010001010101;
        state.memory_mut().data = vec![
            (Addr::new(0x000000000006DFE4), Permissions::Execute, vec![0x08, 0x08]),
            (Addr::new(0x00003FFFFFFE4E08), Permissions::ReadWrite, vec![0x00; 1]),
        ].into_boxed_slice();
        let ok = o.observe(&state);
        println!("Observation result: {}", ok.is_ok());
        println!("Observation result: {ok:?}");
    }*/
    
    let mut o = FindDiffOracle::new(
        GhidraOracle::new(),
        VmOracleSource::new(None, 1).start().into_iter().next().unwrap(),
    );

    let encodings = "semantics/amd-7700x.json";
    let num_instrs_per_encoding = 100;

    let encodings: Vec<Encoding<X64Arch, SynthesizedComputation>> =
        serde_json::from_reader(BufReader::new(File::open(&encodings).unwrap())).unwrap();
    for e in encodings.into_iter().take(5) {
        // 1. run with best_instr
        if let Some(instr) = e.best_instr() {
            let _ = MemoryAccessAnalysis::infer::<X64Arch, _>(&mut o, &instr);
        }

        // 2. estimate number of instructions within encoding
        let num_instrs = 2u32.pow(e.num_wildcard_bits() as u32);

        // 3. if smaller than threshold, run with all instructions,
        //    otherwise run with a random sample of instructions
        if num_instrs <= num_instrs_per_encoding {
            for instr in e.iter_instrs(&[None], true) {
                let _ = MemoryAccessAnalysis::infer::<X64Arch, _>(&mut o, &instr);
            }
        } else {
            for instr in e.random_instrs(&[None], &mut rand::thread_rng()) {
                let _ = MemoryAccessAnalysis::infer::<X64Arch, _>(&mut o, &instr);
            }
        }

        println!("Differences found: {}", o.diffs.len());
        o.diffs.clear();
    }


    args.run(|_| GhidraOracleSource::new(), PrefixScope);
}
