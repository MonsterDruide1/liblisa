use clap::Parser;
use liblisa::{arch::x64::{PrefixScope, X64Arch}, oracle::OracleSource};
use liblisa_libcli::CliCommand;
use liblisa_ghidra_x64_observer::{GhidraOracleSource, GhidraOracle};
use log::trace;
use std::process::exit;
use std::fs::File;
use std::io::BufReader;
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

    /*{
        fn parse_hex(s: &str) -> Vec<u8> {
            s.as_bytes()
                .chunks(2)
                .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
                .collect::<Vec<u8>>()
        }
        fn parse_hex_rev(s: &str) -> Vec<u8> {
            let mut v = parse_hex(s);
            v.reverse();
            v
        }
        let mut o = GhidraVerifierOracleSource::new().start().into_iter().next().unwrap();
        let mut state = SystemState::<X64Arch> {
            cpu: Box::new(X64State::default()),
            memory: MemoryState::default(),
            contains_valid_addrs: true,
            use_trap_flag: false,
        };
        state.cpu_mut().regs[GpReg::Rip as usize] = 0x4E20;
        state.cpu_mut().regs[GpReg::Rax as usize] = 0x0FFE;
        state.cpu_mut().x87.exception_flags = 0x100000000;
        state.memory_mut().data = vec![
            (Addr::new(0x4E20), Permissions::Execute, vec![0xd9, 0x28]),
            (Addr::new(0x0FFE), Permissions::Read, vec![0x28, 0x8f]),
            //(Addr::new(0xFFFFFFFFFFFFBDAB), Permissions::ReadWrite, parse_hex("c2505ffff8bfffff00000002000000870c200000fe4afffffffffff5b8109dbf")),
        ].into_boxed_slice();
        //let state: SystemState::<X64Arch> = serde_json::from_reader(BufReader::new(File::open("state.json").unwrap())).unwrap();
        for i in 0..100 {
            let ok = o.observe(&state);
            if !ok.is_ok() {
                println!("Observation failed on run {}: {:?}", i, ok);
                break;
            }
        }
        let ok = o.observe(&state);
        println!("State: {state:?}");
        println!("Observation result: {}", ok.is_ok());
        println!("Observation result: {ok:?}");
        exit(1);
    }*/
    if false {
        let mut o = GhidraVerifierOracleSource::new().start().into_iter().next().unwrap();
        let state: SystemState::<X64Arch> = serde_json::from_reader(BufReader::new(File::open("state.json").unwrap())).unwrap();
        let ok = o.observe(&state);
        println!("Observation result: {}", ok.is_ok());
        println!("Observation result: {ok:?}");
        exit(1);
    }

    let args = CliCommand::<X64Arch>::parse();
    trace!("Args: {args:#?}");
    args.run(|_| GhidraVerifierOracleSource::new(), PrefixScope);
}
