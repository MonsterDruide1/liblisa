use std::marker::PhantomData;

use liblisa::{oracle::{MappableArea, Oracle}, state::Addr};
use liblisa_ghidra_x64_observer::GhidraOracle;
use liblisa_x64_observer::VmOracleSource;
use nix::sched::CpuSet;
use rand::{Rng, SeedableRng};
use rand_xoshiro::Xoshiro256PlusPlus;

use crate::diff_work::DiffThreadState;

pub fn create_dummy_oracle_source<A: liblisa::arch::Arch>(_: CpuSet) -> impl liblisa::oracle::OracleSource<Oracle = impl liblisa::oracle::Oracle<A>> {
    DummyOracleSource::<A> {
        _phantom: PhantomData,
    }
}

#[derive(Clone, Debug)]
pub struct DoubleCheckedMappableArea<A: MappableArea, B: MappableArea>(A, B);

impl<A: MappableArea, B: MappableArea> MappableArea for DoubleCheckedMappableArea<A, B> {
    fn can_map(&self, addr: Addr) -> bool {
        self.0.can_map(addr) && self.1.can_map(addr)
    }
}

struct DummyOracleSource<A: liblisa::arch::Arch> {
    _phantom: PhantomData<A>,
}

impl<A: liblisa::arch::Arch> liblisa::oracle::OracleSource for DummyOracleSource<A> {
    type Oracle = DummyOracle<A>;

    fn start(&self) -> Vec<Self::Oracle> {
        let o1 = GhidraOracle::new();
        let o2 = VmOracleSource::new(None, 1).start().into_iter().next().unwrap();
        let mappable: DoubleCheckedMappableArea<liblisa_ghidra_x64_observer::GhidraMappableArea, liblisa_x64_observer::VmMappableArea> = DoubleCheckedMappableArea(o1.mappable_area(), o2.mappable_area());
        let state = DiffThreadState {
            o1,
            o2,
            mappable,
            diffs: vec![],
            rng: Xoshiro256PlusPlus::seed_from_u64(rand::thread_rng().r#gen())
        };
        vec![DummyOracle {
            state,
            _phantom: PhantomData,
        }]
    }
}

#[derive(Clone, Debug)]
pub struct DummyMappableArea;
impl MappableArea for DummyMappableArea {
    fn can_map(&self, _addr: liblisa::state::Addr) -> bool {
        true
    }
}

pub struct DummyOracle<A: liblisa::arch::Arch> {
    pub state: DiffThreadState,
    _phantom: PhantomData<A>,
}

impl<A: liblisa::arch::Arch> liblisa::oracle::Oracle<A> for DummyOracle<A> {
    type MappableArea = DummyMappableArea;
    
    const UNRELIABLE_INSTRUCTION_FETCH_ERRORS: bool = false;
    
    fn mappable_area(&self) -> Self::MappableArea {
        todo!()
    }
    
    fn page_size(&mut self) -> u64 {
        todo!()
    }
    
    fn observe(&mut self, before: &liblisa::state::SystemState<A>) -> Result<liblisa::state::SystemState<A>, liblisa::oracle::OracleError> {
        todo!()
    }
    
    fn batch_observe_iter<'a, S: liblisa::state::AsSystemState<A> + 'a, I: IntoIterator<Item = S> + 'a>(
        &'a mut self, states: I,
    ) -> impl Iterator<Item = liblisa::oracle::Observation<S, A>> {
        todo!();
        vec![].into_iter()
    }
    
    fn batch_observe_gpreg_only_iter<'a, S: liblisa::state::AsSystemState<A> + 'a, I: IntoIterator<Item = S> + 'a>(
        &'a mut self, states: I,
    ) -> impl Iterator<Item = liblisa::oracle::Observation<S, A>> {
        todo!();
        vec![].into_iter()
    }
    
    fn scan_memory_accesses(&mut self, before: &liblisa::state::SystemState<A>) -> Result<Vec<liblisa::state::Addr>, liblisa::oracle::OracleError> {
        todo!()
    }
    
    fn debug_dump(&mut self) {
        todo!()
    }
    
    fn restart(&mut self) {
        todo!()
    }
    
    fn kill(self) {
        todo!()
    }
    
    fn debug_dump_state(&mut self, state: &liblisa::state::SystemState<A>) {
        todo!()
    }
}
