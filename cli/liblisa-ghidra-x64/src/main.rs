use clap::Parser;
use liblisa::arch::x64::{PrefixScope, X64Arch};
use liblisa_libcli::CliCommand;
use liblisa_ghidra_x64_observer::GhidraOracleSource;
use log::trace;

pub fn main() {
    env_logger::init();

    let args = CliCommand::<X64Arch>::parse();
    trace!("Args: {args:#?}");

    args.run(|_| GhidraOracleSource::new(), PrefixScope);
}
