use clap::Parser;
use liblisa::{arch::x64::{PrefixScope, X64Arch}, oracle::OracleSource};
use liblisa_libcli::CliCommand;
use liblisa_ghidra_x64_observer::{GhidraOracleSource, GhidraOracle};
use log::trace;
use liblisa_x64_observer::{VmOracle, VmOracleSource};

use liblisa::oracle::Oracle;
use liblisa::state::Permissions;
use liblisa::state::Addr;
use liblisa::arch::x64::GpReg;
use liblisa::state::MemoryState;
use liblisa::arch::x64::X64State;
use liblisa::state::SystemState;

use crate::oracle::GhidraVerifyOracle;

pub mod oracle;

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

    args.run(|_| GhidraOracleSource::new(), PrefixScope);
}
