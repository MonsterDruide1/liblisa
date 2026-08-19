use clap::Parser;
use liblisa::{Instruction, arch::x64::X64Arch};
use liblisa_enc::AccessAnalysisError;

use crate::{diff::{create_state, run_instr}, diff_action::DiffCommand};

pub mod state_diff;
pub mod diff_action;
pub mod dummy_oracle_source;
pub mod diff_work;
pub mod diff;
pub mod diff_types;
pub mod diff_postprocess;

#[derive(clap::Parser)]
enum CliCommand {
    Diff(DiffCommand),
    Test {
        instr: Instruction,
    },
}

impl CliCommand {
    pub fn run(self) {
        match self {
            CliCommand::Diff(cmd) => cmd.run(),
            CliCommand::Test { instr } => {
                let mut state = create_state();
                println!("Running instruction...");
                println!("{:?}", run_instr(&instr, diff_types::NUM_STATES_PER_INSTR, &mut state));
                println!("Observed diffs: {:?}", state.diffs);
                println!("First diff as json:");
                if let Some(x) = state.diffs.get(0) {
                    serde_json::to_writer(std::io::stdout(), &x.example_before).unwrap();
                }
                println!("");
                println!("Postprocessing diffs...");
                unsafe {
                    let (explained, unexplained) = diff_postprocess::postprocess_all(
                        &diff_types::Diff { items: vec![diff_types::DiffItem {
                            instructions: vec![], description: "<missing>".to_string(),
                            result: Some(diff_types::DiffResult {diffs: Ok(state.diffs)})
                        }], runtime_ms: 0, total_ms: 0 },
                    );
                    println!("Explained diffs: {:?}", explained);
                    println!("Unexplained diffs: {:?}", unexplained);
                }
            }
        }
    }
}

pub fn main() -> Result<(), AccessAnalysisError<X64Arch>> {
    env_logger::init();

    CliCommand::parse().run();

    Ok(())
}
