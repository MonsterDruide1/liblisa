use clap::Parser;
use liblisa::{arch::x64::{PrefixScope, X64Arch}, oracle::{OracleSource, VerifyOracle}};
use liblisa_libcli::CliCommand;
use liblisa_ghidra_x64_observer::{GhidraOracle, GhidraOracleSource};
use log::trace;
use liblisa_x64_observer::{VmOracle, VmOracleSource};

use liblisa::oracle::Oracle;
use liblisa::state::Permissions;
use liblisa::state::Addr;
use liblisa::arch::x64::GpReg;
use liblisa::state::MemoryState;
use liblisa::arch::x64::X64State;
use liblisa::state::SystemState;

pub struct GhidraVerifierOracleSource {}
impl GhidraVerifierOracleSource {
    pub fn new() -> Self {
        Self {}
    }
}
impl OracleSource for GhidraVerifierOracleSource {
    type Oracle = VerifyOracle<X64Arch, GhidraOracle, VmOracle>;

    fn start(&self) -> Vec<Self::Oracle> {
        vec![
            VerifyOracle::new(
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

    /*let mut o = GhidraVerifierOracleSource::new().start().into_iter().next().unwrap();
    let mut state = SystemState::<X64Arch> {
        cpu: Box::new(X64State::default()),
        memory: MemoryState::default(),
        contains_valid_addrs: true,
        use_trap_flag: false,
    };
    state.cpu_mut().regs[GpReg::Rip as usize] = 0x00003FFFFFFFFF64;
    state.cpu_mut().regs[GpReg::Rax as usize] = 0x00003FFFFFFFFFFF;
    state.memory_mut().data = vec![
        (Addr::new(0x3FFFFFFFFF64), Permissions::Execute, vec![0x31, 0x00]),
    ].into_boxed_slice();
    let ok = o.observe(&state);*/

    for trap in vec![true, false] {
        for i in 0xF82B3FFFFFFFFFFC..=0xF82B3FFFFFFFFFFF {
            let p = std::panic::catch_unwind(|| {
                let mut o = GhidraVerifierOracleSource::new().start().into_iter().next().unwrap();
                let mut state = SystemState::<X64Arch> {
                    cpu: Box::new(X64State::default()),
                    memory: MemoryState::default(),
                    contains_valid_addrs: true,
                    use_trap_flag: trap,
                };
                state.cpu_mut().regs[GpReg::Rip as usize] = 0x00003FFFFFFFFFF6;
                state.cpu_mut().regs[GpReg::Rax as usize] = i;
                state.memory_mut().data = vec![
                    (Addr::new(0x3FFFFFFFFFF6), Permissions::Execute, vec![0x66, 0x01, 0x00]),
                ].into_boxed_slice();
                let ok = o.observe(&state);

                println!("OK: {ok:X?}, trap_flag={trap}, addr={i:X?}");

                ()
            });
            if p.is_err() {
                println!("Panic occurred during observation with trap_flag={trap}, addr={i:X?}");
            }
        }
    }
    return;

    args.run(|_| GhidraVerifierOracleSource::new(), PrefixScope);
}
