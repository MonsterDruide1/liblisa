use std::fmt;
use std::time::Instant;

use liblisa::arch::{Arch, x64::X64Arch};
use liblisa::encoding::Encoding;
use liblisa::oracle::Oracle;
use liblisa::semantics::default::computation::SynthesizedComputation;
use liblisa_enc::AccessAnalysisError;
use rand::Rng;
use serde::{Deserialize, Serialize};

use liblisa_libcli::threadpool::work::Work;

use crate::diff::run_instr;
use crate::diff_types::*;
use crate::dummy_oracle_source::DummyOracle;
use crate::state_diff::Difference;

impl DiffRequest {
    pub fn diff<A: Arch, O: Oracle<A>, R: Rng>(
        &self, oracle: &mut O, rng: &mut R,
    ) -> Result<Vec<Difference>, AccessAnalysisError<X64Arch>> {
        let oracle: &mut DummyOracle<X64Arch> = unsafe {
            &mut *(oracle as *mut O as *mut DummyOracle<X64Arch>)
        };
        let mut state = &mut oracle.state;

        for instr in &self.todo.instructions {
            run_instr(instr, NUM_STATES_PER_INSTR, &mut state)?;
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

impl<A: Arch> Work<A, ()> for Diff
{
    type RuntimeData = DiffRuntimeData;
    type Request = DiffRequest;
    type Result = DiffResult;
    type Artifact = DiffArtifact;

    fn next(&mut self, data: &mut Self::RuntimeData) -> Option<Self::Request> {
        let next_entry = self.remaining_entries.iter().find(|e| !data.pending.contains(e));

        next_entry.and_then(|&encoding_index| {
            self.todos.get(encoding_index).cloned().map(|todo| {
                let request = DiffRequest {
                    at: Instant::now(),
                    encoding_index,
                    todo,
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
            "Received result for {} index={} in {}s: {}",
            request.todo.description,
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
        println!("Diffing [{}] {}", request.encoding_index, request.todo.description);
        let result = request.diff(oracle, &mut rand::thread_rng());
        DiffResult { diffs: result }
    }
}

impl Diff {
    pub fn create(encodings: Vec<Encoding<X64Arch, SynthesizedComputation>>) -> Self {
        let todos: Vec<DiffTodoItem> = encodings.iter().enumerate().map(|(i, encoding)| {
            if i % 100 == 0 {
                println!("Preparing diff for encoding {}: {}", i, encoding);
            }
            // estimate number of instructions within encoding
            let num_instrs = 2_usize.checked_pow(encoding.num_wildcard_bits() as u32);
            let use_all = if let Some(num_instrs) = num_instrs {
                num_instrs <= NUM_INSTRS_PER_ENCODING
            } else {
                false
            };

            // if smaller than threshold, run with all instructions,
            //   otherwise run with a random sample of instructions
            let mut instrs = if use_all {
                encoding.iter_instrs(&[None; 10000], true).collect::<Vec<_>>()
            } else {
                encoding.random_instrs(&[None; 10000], &mut rand::thread_rng()).take(NUM_INSTRS_PER_ENCODING).collect::<Vec<_>>()
            };
            DiffTodoItem {
                instructions: instrs,
                description: format!("{}", encoding),
            }
        }).collect();

        let remaining_entries = (0..todos.len()).collect();

        Diff {
            runtime_ms: 0,
            total_ms: 0,
            todos,
            remaining_entries,
            results: Vec::new(),
        }
    }
}
