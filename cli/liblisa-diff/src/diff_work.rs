use std::fmt;
use std::time::Instant;

use liblisa::arch::{Arch, x64::X64Arch};
use liblisa::encoding::Encoding;
use liblisa::oracle::Oracle;
use liblisa::semantics::default::computation::SynthesizedComputation;
use liblisa_enc::AccessAnalysisError;
use liblisa_ghidra_x64_observer::GhidraOracle;
use liblisa_x64_observer::VmOracle;
use rand::Rng;
use rand_xoshiro::Xoshiro256PlusPlus;
use serde::{Deserialize, Serialize};

use liblisa_libcli::threadpool::work::Work;

use crate::diff::run_instr;
use crate::dummy_oracle_source::{DoubleCheckedMappableArea, DummyOracle};
use crate::state_diff::Difference;

const NUM_INSTRS_PER_ENCODING: usize = 100;
const NUM_STATES_PER_INSTR: usize = 2500;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Diff<A: Arch> {
    #[serde(default)]
    pub runtime_ms: u128,
    pub total_ms: u128,
    pub encodings: Vec<Encoding<A, SynthesizedComputation>>,
    pub remaining_entries: Vec<usize>,
    pub results: Vec<(usize, DiffResult)>,
}

pub struct DiffRuntimeData {
    pub last_check: Instant,
    pub pending: Vec<usize>,
}

pub struct DiffRequest<A: Arch> {
    at: Instant,
    encoding_index: usize,
    encoding: Encoding<A, SynthesizedComputation>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiffResult {
    pub diffs: Result<Vec<Difference>, AccessAnalysisError<X64Arch>>,
}

pub struct DiffThreadState {
    pub o1: GhidraOracle,
    pub o2: VmOracle,
    pub mappable: DoubleCheckedMappableArea<<GhidraOracle as Oracle<X64Arch>>::MappableArea, <VmOracle as Oracle<X64Arch>>::MappableArea>,
    pub diffs: Vec<Difference>,
    pub rng: Xoshiro256PlusPlus,
}

impl<A: Arch> std::fmt::Debug for DiffRequest<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiffRequest")
            .field("at", &self.at)
            .field("index", &self.encoding_index)
            .finish()
    }
}

impl<A: Arch> DiffRequest<A> {
    pub fn diff<O: Oracle<A>, R: Rng>(
        &self, oracle: &mut O, rng: &mut R,
    ) -> Result<Vec<Difference>, AccessAnalysisError<X64Arch>> {
        let oracle: &mut DummyOracle<X64Arch> = unsafe {
            &mut *(oracle as *mut O as *mut DummyOracle<X64Arch>)
        };
        let mut state = &mut oracle.state;

        // 1. run with best_instr
        if let Some(instr) = self.encoding.best_instr() {
            run_instr(&instr, NUM_STATES_PER_INSTR, &mut state)?;
        }

        // 2. estimate number of instructions within encoding
        let num_instrs = 2_usize.pow(self.encoding.num_wildcard_bits() as u32);

        // 3. if smaller than threshold, run with all instructions,
        //    otherwise run with a random sample of instructions
        let iterator = if num_instrs <= NUM_INSTRS_PER_ENCODING {
            self.encoding.iter_instrs(&[None; 10000], true).collect::<Vec<_>>()
        } else {
            self.encoding.random_instrs(&[None; 10000], &mut rand::thread_rng()).take(NUM_INSTRS_PER_ENCODING).collect::<Vec<_>>()
        };
        for instr in iterator {
            run_instr(&instr, NUM_STATES_PER_INSTR, &mut state)?;
        }

        let diffs = std::mem::take(&mut state.diffs);
        Ok(diffs)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiffArtifact {
    pub ms_taken: u128,
    pub result: DiffResult,
}

impl<A: Arch> Work<A, ()> for Diff<A>
{
    type RuntimeData = DiffRuntimeData;
    type Request = DiffRequest<A>;
    type Result = DiffResult;
    type Artifact = DiffArtifact;

    fn next(&mut self, data: &mut Self::RuntimeData) -> Option<Self::Request> {
        let next_entry = self.remaining_entries.iter().find(|e| !data.pending.contains(e));

        next_entry.and_then(|&encoding_index| {
            self.encodings.get(encoding_index).cloned().map(|encoding| {
                let request = DiffRequest {
                    at: Instant::now(),
                    encoding_index,
                    encoding,
                };

                data.pending.push(encoding_index);

                request
            })
        })
    }

    fn complete(
        &mut self, data: &mut Self::RuntimeData, request: Self::Request, result: Self::Result,
    ) -> Option<Self::Artifact> {
        let ms_step = data.last_check.elapsed().as_millis();
        self.runtime_ms += ms_step;
        data.last_check = Instant::now();

        let ms_taken = request.at.elapsed().as_millis();
        self.total_ms += ms_taken;

        let result_type = match &result.diffs {
            Ok(diffs) => format!("{} diffs", diffs.len()),
            Err(e) => format!("Error: {}", e),
        };
        println!(
            "Received result for {:X} index={} in {}s: {}",
            request.encoding.instr(),
            request.encoding_index,
            request.at.elapsed().as_secs(),
            result_type,
        );

        self.results.push((request.encoding_index, result.clone()));
        self.remaining_entries.remove(
            self.remaining_entries
                .iter()
                .position(|&item| item == request.encoding_index)
                .unwrap(),
        );

        Some(DiffArtifact {
            ms_taken,
            result,
        })
    }

    fn run<O: Oracle<A>>(oracle: &mut O, _cache: &(), request: &Self::Request) -> Self::Result {
        println!("Diffing {}", request.encoding);
        let result = request.diff(oracle, &mut rand::thread_rng());
        DiffResult { diffs: result }
    }
}

impl<A: Arch> Diff<A> {
    pub fn create(encodings: Vec<Encoding<A, SynthesizedComputation>>) -> Self {
        let num_encodings = encodings.len();
        Diff {
            runtime_ms: 0,
            total_ms: 0,
            encodings,
            remaining_entries: (0..num_encodings).collect(),
            results: Vec::new(),
        }
    }
}
