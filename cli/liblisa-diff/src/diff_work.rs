use std::time::Instant;

use liblisa::arch::{Arch, x64::X64Arch};
use liblisa::encoding::Encoding;
use liblisa::oracle::Oracle;
use liblisa::semantics::default::computation::SynthesizedComputation;
use log::error;
use rand::Rng;
use serde::{Deserialize, Serialize};

use liblisa_libcli::threadpool::work::Work;

use crate::diff::{RunResultCounts, run_instr};
use crate::diff_types::*;
use crate::dummy_oracle_source::DummyOracle;

#[derive(Clone, Debug)]
pub struct DiffRequest {
    pub at: Instant,
    pub item_index: usize,
    pub item: DiffItem,
}
impl DiffRequest {
    pub fn diff<A: Arch, O: Oracle<A>, R: Rng>(
        &self, oracle: &mut O, rng: &mut R,
    ) -> DiffResult {
        let oracle: &mut DummyOracle<X64Arch> = unsafe {
            &mut *(oracle as *mut O as *mut DummyOracle<X64Arch>)
        };
        let mut state = &mut oracle.state;

        let mut counts = RunResultCounts { ok: 0, both_gp: 0, unknown: 0 };
        for instr in &self.item.instructions {
            let counts_ = run_instr(instr, NUM_STATES_PER_INSTR, &mut state);
            let counts_ = match counts_ {
                Ok(counts_) => counts_,
                Err(e) => {
                    return DiffResult { diffs: Err(e) };
                }
            };
            counts.ok += counts_.ok;
            counts.both_gp += counts_.both_gp;
            counts.unknown += counts_.unknown;
        }
        if counts.unknown > 0 {
            error!("Instruction keeps throwing unknown errors: {} (ok={}, both_gp={}, unknown={})", self.item.description, counts.ok, counts.both_gp, counts.unknown);
            return DiffResult { diffs: Err(DiffError::InstructionKeepsFaulting) };
        }
        if counts.ok == 0 && counts.both_gp > 0 {
            return DiffResult { diffs: Err(DiffError::InstructionKeepsGeneralFaulting) };
        }
        let diffs = std::mem::take(&mut state.diffs);
        return DiffResult { diffs: Ok(diffs) };
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiffArtifact {
    pub ms_taken: u128,
    pub result: DiffResult,
}

pub struct DiffRuntimeData {
    last_check: Instant,
    todo: Vec<usize>,
    pending: Vec<usize>,
}
impl DiffRuntimeData {
    pub fn from_diff(diff: &Diff) -> Self {
        let todo = (0..diff.items.len()).filter(|&i| diff.items[i].result.is_none()).collect();
        DiffRuntimeData {
            last_check: Instant::now(),
            pending: Vec::new(),
            todo,
        }
    }
}

impl<A: Arch> Work<A, ()> for Diff
{
    type RuntimeData = DiffRuntimeData;
    type Request = DiffRequest;
    type Result = DiffResult;
    type Artifact = DiffArtifact;

    fn next(&mut self, data: &mut Self::RuntimeData) -> Option<Self::Request> {
        let next_entry = data.todo.iter().find(|e| !data.pending.contains(e));

        next_entry.and_then(|&item_index| {
            self.items.get(item_index).cloned().map(|item| {
                let request = DiffRequest {
                    at: Instant::now(),
                    item_index,
                    item,
                };

                data.pending.push(item_index);

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
            request.item.description,
            request.item_index,
            request.at.elapsed().as_secs(),
            result_type,
        );

        self.items[request.item_index].result = Some(result.clone());
        data.todo.remove(
            data.todo
                .iter()
                .position(|&item| item == request.item_index)
                .unwrap(),
        );

        Some(DiffArtifact {
            ms_taken,
            result,
        })
    }

    fn run<O: Oracle<A>>(oracle: &mut O, _cache: &(), request: &Self::Request) -> Self::Result {
        println!("Diffing [{}] {}", request.item_index, request.item.description);
        request.diff(oracle, &mut rand::thread_rng())
    }
}

impl Diff {
    pub fn create(encodings: Vec<Encoding<X64Arch, SynthesizedComputation>>) -> Self {
        let items: Vec<DiffItem> = encodings.iter().enumerate().map(|(i, encoding)| {
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
            let instrs = if use_all {
                encoding.iter_instrs(&[None; 10000], true).collect::<Vec<_>>()
            } else {
                encoding.random_instrs(&[None; 10000], &mut rand::thread_rng()).take(NUM_INSTRS_PER_ENCODING).collect::<Vec<_>>()
            };
            DiffItem {
                instructions: instrs,
                description: format!("{}", encoding),
                result: None,
            }
        }).collect();

        Diff {
            runtime_ms: 0,
            total_ms: 0,
            items,
        }
    }
}
