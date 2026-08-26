use rand_xoshiro::Xoshiro256PlusPlus;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use liblisa::Instruction;
use liblisa::arch::x64::X64Arch;
use liblisa::oracle::Oracle;
use liblisa::state::random::RandomizationError;
use liblisa_ghidra_x64_observer::GhidraOracle;
use liblisa_x64_observer::VmOracle;

use crate::dummy_oracle_source::DoubleCheckedMappableArea;
use crate::state_diff::Difference;


pub const NUM_INSTRS_PER_ENCODING: usize = 100;
pub const NUM_STATES_PER_INSTR: usize = 250;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Diff {
    #[serde(default)]
    pub runtime_ms: u128,
    pub total_ms: u128,
    pub items: Vec<DiffItem>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiffItem {
    pub instructions: Vec<Instruction>,
    pub description: String,
    pub result: Option<DiffResult>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiffResult {
    pub diffs: Result<Vec<Difference>, DiffError>,
}

pub struct DiffThreadState {
    pub o1: GhidraOracle,
    pub o2: VmOracle,
    pub mappable: DoubleCheckedMappableArea<<GhidraOracle as Oracle<X64Arch>>::MappableArea, <VmOracle as Oracle<X64Arch>>::MappableArea>,
    pub diffs: Vec<Difference>,
    pub rng: Xoshiro256PlusPlus,
}

#[derive(Error, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DiffError {
    // should not happen => results need to be checked for reason:
    #[error("??? instruction keeps faulting ???")]
    InstructionKeepsFaulting,

    // cannot be handled, abort diffing and report to user:
    #[error("randomization error: {0}")]
    RandomizationError(RandomizationError),
    #[error("invalid instruction on Ghidra={0} or VM={1}")]
    InvalidInstruction(bool, bool),
    #[error("Ghidra requires custom Pcode op")]
    GhidraCustomPcodeOp,
    #[error("Ghidra attempted to use a varnode that is too large")]
    GhidraVarnodeTooLarge,
    #[error("Ghidra reported unimplemented emulation")]
    GhidraEmulationUnimplemented,
    #[error("keeps throwing GP errors")]
    InstructionKeepsGeneralFaulting,
    #[error("keeps throwing GPs due to unaligned addresses")]
    UnalignedAccessKeepsFaulting,
}

impl From<RandomizationError> for DiffError {
    fn from(e: RandomizationError) -> Self {
        DiffError::RandomizationError(e)
    }
}
