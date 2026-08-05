use clap::Parser;
use liblisa::arch::x64::X64Arch;
use liblisa_enc::AccessAnalysisError;

pub mod state_diff;
pub mod diff_action;
pub mod dummy_oracle_source;
pub mod diff_work;
pub mod diff;

pub fn main() -> Result<(), AccessAnalysisError<X64Arch>> {
    env_logger::init();

    diff_action::DiffCommand::parse().run();

    Ok(())
}
