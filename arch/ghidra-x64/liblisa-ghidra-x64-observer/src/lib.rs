use std::iter::{once};

use liblisa::arch::x64::{X64Arch};
use liblisa::arch::fake::AnyArea;
use liblisa::oracle::{FallbackBatchObserveIter, Observation, Oracle, OracleError, OracleSource};
use liblisa::state::{Addr, AsSystemState, SystemState};

use crate::ghidra::GhidraObserver;

pub mod ghidra;

pub struct GhidraOracle {
    observer: GhidraObserver,
}
impl GhidraOracle {
    pub fn new() -> Self {
        Self { observer: GhidraObserver::new() }
    }
}
impl Oracle<X64Arch> for GhidraOracle {
    type MappableArea = AnyArea;
    const UNRELIABLE_INSTRUCTION_FETCH_ERRORS: bool = false;

    fn mappable_area(&self) -> Self::MappableArea {
        AnyArea {}
    }

    fn page_size(&mut self) -> u64 {
        4096
    }

    fn observe(&mut self, before: &SystemState<X64Arch>) -> Result<SystemState<X64Arch>, OracleError> {
        self.observer.observe(before)
    }

    fn scan_memory_accesses(&mut self, before: &SystemState<X64Arch>) -> Result<Vec<Addr>, OracleError> {
        self.observer.scan_memory_accesses(before)
    }

    fn debug_dump(&mut self) {
        self.observer.debug_dump();
        println!("{:#?}", self.observer);
    }

    fn restart(&mut self) {
        // TODO: Do we need this?
    }

    fn kill(self) {
        drop(self)
    }

    fn batch_observe_iter<'a, S: AsSystemState<X64Arch> + 'a, I: IntoIterator<Item = S> + 'a>(
        &'a mut self, states: I,
    ) -> impl Iterator<Item = Observation<S, X64Arch>> {
        FallbackBatchObserveIter::new(self, states.into_iter())
    }

    fn batch_observe_gpreg_only_iter<'a, S: AsSystemState<X64Arch> + 'a, I: IntoIterator<Item = S> + 'a>(
        &'a mut self, states: I,
    ) -> impl Iterator<Item = Observation<S, X64Arch>> {
        self.batch_observe_iter(states)
    }
}

pub struct GhidraOracleSource {}
impl GhidraOracleSource {
    pub fn new() -> Self {
        Self {}
    }
}
impl OracleSource for GhidraOracleSource {
    type Oracle = GhidraOracle;

    fn start(&self) -> Vec<Self::Oracle> {
        vec![GhidraOracle::new()]
    }
}
