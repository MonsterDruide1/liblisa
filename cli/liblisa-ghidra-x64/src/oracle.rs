use std::marker::PhantomData;

use liblisa::arch::CpuState;
use liblisa::arch::x64::{GpReg, X64Arch, X64Flag};
use liblisa::oracle::Observation;
use liblisa::oracle::{FallbackBatchObserveIter, MappableArea, Oracle, OracleError};
use liblisa::state::{Addr, AsSystemState, SystemState};
use log::warn;

/// An oracle that observes execution on two oracles, and panics if the results are not identical.
pub struct GhidraVerifyOracle<O1: Oracle<X64Arch>, O2: Oracle<X64Arch>>(O1, O2, PhantomData<X64Arch>);

impl<O1: Oracle<X64Arch>, O2: Oracle<X64Arch>> GhidraVerifyOracle<O1, O2> {
    /// Creates a new [`GhidraVerifyOracle`], which verifies the observations of `o1` against the observations of `o2`.
    pub fn new(o1: O1, o2: O2) -> GhidraVerifyOracle<O1, O2> {
        GhidraVerifyOracle(o1, o2, PhantomData)
    }
}

#[derive(Clone, Debug)]
pub struct DoubleCheckedMappableArea<A: MappableArea, B: MappableArea>(A, B);

impl<A: MappableArea, B: MappableArea> MappableArea for DoubleCheckedMappableArea<A, B> {
    fn can_map(&self, addr: Addr) -> bool {
        self.0.can_map(addr) && self.1.can_map(addr)
    }
}

fn is_mismatch_ok(before: &SystemState<X64Arch>, r1: &SystemState<X64Arch>, r2: &SystemState<X64Arch>) -> bool {
    let pc = CpuState::<X64Arch>::gpreg(before.cpu(), GpReg::Rip);
    let instruction = before.memory().iter().find_map(|(addr, _, data)| {
        let offset = pc.checked_sub(addr.as_u64())?;
        if (offset as usize) < data.len() {
            Some(&data[offset as usize..])
        } else {
            None
        }
    }).unwrap_or(&[]);

    // OR: The state of the AF flag is undefined.  (Vol. 2B, 4-163)
    if instruction.len() == 2 && instruction[0] == 0x08 {
        let mut r1c = r1.clone();
        CpuState::<X64Arch>::set_flag(r1c.cpu_mut(), X64Flag::Af, CpuState::<X64Arch>::flag(r2.cpu(), X64Flag::Af));
        return r1c == *r2;
    }
    false
}

impl<O1: Oracle<X64Arch>, O2: Oracle<X64Arch>> Oracle<X64Arch> for GhidraVerifyOracle<O1, O2> {
    type MappableArea = DoubleCheckedMappableArea<O1::MappableArea, O2::MappableArea>;
    const UNRELIABLE_INSTRUCTION_FETCH_ERRORS: bool =
        O1::UNRELIABLE_INSTRUCTION_FETCH_ERRORS || O2::UNRELIABLE_INSTRUCTION_FETCH_ERRORS;

    fn mappable_area(&self) -> Self::MappableArea {
        DoubleCheckedMappableArea(self.0.mappable_area(), self.1.mappable_area())
    }

    fn page_size(&mut self) -> u64 {
        assert_eq!(self.0.page_size(), self.1.page_size());
        self.0.page_size()
    }

    fn observe(&mut self, before: &SystemState<X64Arch>) -> Result<SystemState<X64Arch>, OracleError> {
        use OracleError::*;
        let r1 = self.0.observe(before);
        let mut r2 = self.1.observe(before);
        
        if let Ok(r2e) = &r2 {
            let rip_before = CpuState::<X64Arch>::gpreg(before.cpu(), GpReg::Rip);
            let mut rip_after = CpuState::<X64Arch>::gpreg(r2e.cpu(), GpReg::Rip);
            while rip_before == rip_after {
                warn!("Warning: Oracle did not advance RIP: {rip_before:X} -> {rip_after:X}");
                r2 = self.1.observe(before);
                rip_after = CpuState::<X64Arch>::gpreg(r2.as_ref().unwrap().cpu(), GpReg::Rip);
                warn!("Now: {rip_after:X}");
            }
        }

        assert!(
            match (&r1, &r2) {
                (Ok(a), Ok(b)) if a == b => true,
                (Err(a), Err(b)) => match (a, b) {
                    (MemoryAccess(a), MemoryAccess(b)) if a == b => true,
                    (InstructionFetchMemoryAccess(a), InstructionFetchMemoryAccess(b)) if a == b => true,
                    (InvalidInstruction, InvalidInstruction) => true,
                    (GeneralFault, GeneralFault) => true,
                    (ComputationError, ComputationError) => true,
                    _ => false,
                },
                (Ok(r1), Ok(r2)) => {
                    if is_mismatch_ok(before, &r1, &r2) {
                        true
                    } else {
                        println!("Observations don't match: {before:X?} results in {r1:X?} vs {r2:X?}");
                        self.debug_dump();

                        for _ in 0..1000 {
                            let rprime1 = self.0.observe(before);
                            let rprime2 = self.1.observe(before);

                            println!(
                                "Repeating yields: equal={} for first / equal={} for second",
                                rprime1.as_ref().unwrap() == r1.as_ref(),
                                rprime2.as_ref().unwrap() == r2.as_ref()
                            );
                        }

                        false
                    }
                },
                _ => false,
            },
            "Observations don't match: {before:X?} results in {r1:X?} vs {r2:X?}"
        );

        r1
    }

    fn scan_memory_accesses(&mut self, before: &SystemState<X64Arch>) -> Result<Vec<Addr>, OracleError> {
        let r1 = self.0.scan_memory_accesses(before)?;
        let r2 = self.1.scan_memory_accesses(before)?;

        assert_eq!(r1, r2);
        Ok(r1)
    }

    fn debug_dump(&mut self) {
        println!("First:");
        self.0.debug_dump();

        println!();
        println!("Second:");
        self.1.debug_dump();
    }

    fn debug_dump_state(&mut self, state: &SystemState<X64Arch>) {
        println!("First:");
        self.0.debug_dump_state(state);

        println!();
        println!("Second:");
        self.1.debug_dump_state(state);
    }

    fn restart(&mut self) {
        self.0.restart();
        self.1.restart();
    }

    fn kill(self) {
        self.0.kill();
        self.1.kill();
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
