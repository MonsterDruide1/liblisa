use std::time::Instant;
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
pub struct DiffTodoItem {
    pub instructions: Vec<Instruction>,
    pub description: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Diff {
    #[serde(default)]
    pub runtime_ms: u128,
    pub total_ms: u128,
    pub todos: Vec<DiffTodoItem>,
    pub remaining_entries: Vec<usize>,
    pub results: Vec<(usize, DiffResult)>,
}

pub struct DiffRuntimeData {
    pub last_check: Instant,
    pub pending: Vec<usize>,
}

#[derive(Clone, Debug)]
pub struct DiffRequest {
    pub at: Instant,
    pub encoding_index: usize,
    pub todo: DiffTodoItem,
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

#[derive(Error, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum DiffError {
    // should not happen => results need to be checked for reason:
    #[error("??? instruction keeps faulting ???")]
    InstructionKeepsFaulting,

    // cannot be handled, abort diffing and report to user:
    #[error("unaligned access keeps faulting")]
    UnalignedAccessKeepsFaulting,
    #[error("randomization error: {0}")]
    RandomizationError(RandomizationError),
    #[error("invalid instruction on both systems")]
    InvalidInstruction,
    #[error("Ghidra requires custom Pcode op")]
    GhidraCustomPcodeOp,
    #[error("Ghidra attempted to use a varnode that is too large")]
    GhidraVarnodeTooLarge,
}

impl From<RandomizationError> for DiffError {
    fn from(e: RandomizationError) -> Self {
        DiffError::RandomizationError(e)
    }
}
