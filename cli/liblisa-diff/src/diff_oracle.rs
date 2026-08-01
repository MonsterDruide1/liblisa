use liblisa::arch::{Arch, CpuState};
use liblisa::arch::x64::{GpReg, X64Arch, X64Flag, X87, Xmm};
use liblisa::oracle::Observation;
use liblisa::oracle::{FallbackBatchObserveIter, MappableArea, Oracle, OracleError};
use liblisa::state::{Addr, AsSystemState, SystemState};
use log::warn;

/// An oracle that observes execution on two oracles, and panics if the results are not identical.
pub struct FindDiffOracle<O1: Oracle<X64Arch>, O2: Oracle<X64Arch>> {
    o1: O1,
    o2: O2,
    pub diffs: Vec<Difference>,
}

#[derive(Clone, Debug)]
pub struct Difference {
    pub diff_types: DifferenceType,
    pub example_before: SystemState<X64Arch>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum DifferenceType {
    OkOk(Vec<OkMismatch>),
    OkErr(OracleError),
    ErrOk(OracleError),
    ErrErr(OracleError, OracleError),
}

#[derive(Clone, Debug, PartialEq)]
pub enum OkMismatch {
    // CPU State
    RegMismatch(GpReg, u64, u64),
    XmmMismatch(Xmm, Xmm),
    X87Mismatch(X87, X87),
    XmmExceptionFlagsMismatch(u64, u64),
    XmmDazMismatch(u8, u8),
    // Mem State
    MemoryMismatch(Addr, Vec<u8>, Vec<u8>),
}

impl<O1: Oracle<X64Arch>, O2: Oracle<X64Arch>> FindDiffOracle<O1, O2> {
    /// Creates a new [`FindDiffOracle`], which verifies the observations of `o1` against the observations of `o2`.
    pub fn new(o1: O1, o2: O2) -> FindDiffOracle<O1, O2> {
        FindDiffOracle { o1, o2, diffs: Vec::new() }
    }
}

#[derive(Clone, Debug)]
pub struct DoubleCheckedMappableArea<A: MappableArea, B: MappableArea>(A, B);

impl<A: MappableArea, B: MappableArea> MappableArea for DoubleCheckedMappableArea<A, B> {
    fn can_map(&self, addr: Addr) -> bool {
        self.0.can_map(addr) && self.1.can_map(addr)
    }
}

impl<O1: Oracle<X64Arch>, O2: Oracle<X64Arch>> Oracle<X64Arch> for FindDiffOracle<O1, O2> {
    type MappableArea = DoubleCheckedMappableArea<O1::MappableArea, O2::MappableArea>;
    const UNRELIABLE_INSTRUCTION_FETCH_ERRORS: bool =
        O1::UNRELIABLE_INSTRUCTION_FETCH_ERRORS || O2::UNRELIABLE_INSTRUCTION_FETCH_ERRORS;

    fn mappable_area(&self) -> Self::MappableArea {
        DoubleCheckedMappableArea(self.o1.mappable_area(), self.o2.mappable_area())
    }

    fn page_size(&mut self) -> u64 {
        assert_eq!(self.o1.page_size(), self.o2.page_size());
        self.o1.page_size()
    }

    fn observe(&mut self, before: &SystemState<X64Arch>) -> Result<SystemState<X64Arch>, OracleError> {
        use OracleError::*;
        let r1 = self.o1.observe(before);
        let r2 = self.o2.observe(before);

        // do not search for differences if custom pcode ops are called
        // => implementation of instruction knowingly missing in Ghidra
        if let Err(ApiError(e)) = &r1 {
            if e.contains("Ghidra emulator called a custom pcode op") {
                return r1;
            }
        }

        let difftype = match (&r1, &r2) {
            // observations are identical, nothing to do
            (Ok(r1), Ok(r2)) if r1 == r2 => None,
            (Err(MemoryAccess(a1)), Err(MemoryAccess(a2))) if a1 == a2 => None,
            (Err(InstructionFetchMemoryAccess(a1)), Err(InstructionFetchMemoryAccess(a2))) if a1 == a2 => None,
            (Err(InvalidInstruction), Err(InvalidInstruction)) => None,
            (Err(GeneralFault), Err(GeneralFault)) => None,
            (Err(Unreliable), Err(Unreliable)) => None,
            (Err(ComputationError), Err(ComputationError)) => None,
            (Err(Timeout), Err(Timeout)) => None,
            (Err(MultipleInstructionsExecuted), Err(MultipleInstructionsExecuted)) => None,
            (Err(ApiError(e1)), Err(ApiError(e2))) if e1 == e2 => None,

            // observations are different, record the difference
            (Ok(r1), Ok(r2)) => {
                let mut mismatches = Vec::new();
                for reg in X64Arch::iter_gpregs() {
                    let v1 = CpuState::<X64Arch>::gpreg(r1.cpu(), reg);
                    let v2 = CpuState::<X64Arch>::gpreg(r2.cpu(), reg);
                    if v1 != v2 {
                        mismatches.push(OkMismatch::RegMismatch(reg, v1, v2));
                    }
                }
                if r1.cpu().xmm != r2.cpu().xmm {
                    mismatches.push(OkMismatch::XmmMismatch(r1.cpu().xmm.clone(), r2.cpu().xmm.clone()));
                }
                if r1.cpu().x87 != r2.cpu().x87 {
                    mismatches.push(OkMismatch::X87Mismatch(r1.cpu().x87.clone(), r2.cpu().x87.clone()));
                }
                if r1.cpu().xmm_exception_flags != r2.cpu().xmm_exception_flags {
                    mismatches.push(OkMismatch::XmmExceptionFlagsMismatch(r1.cpu().xmm_exception_flags, r2.cpu().xmm_exception_flags));
                }
                if r1.cpu().xmm_daz != r2.cpu().xmm_daz {
                    mismatches.push(OkMismatch::XmmDazMismatch(r1.cpu().xmm_daz, r2.cpu().xmm_daz));
                }
                for ((addr1, perms1, data1), (addr2, perms2, data2)) in r1.memory().iter().zip(r2.memory().iter()) {
                    assert!(addr1 == addr2 && perms1 == perms2);
                    if data1 != data2 {
                        mismatches.push(OkMismatch::MemoryMismatch(*addr1, data1.clone(), data2.clone()));
                    }
                }
                assert!(mismatches.len() > 0);
                Some(DifferenceType::OkOk(mismatches))
            }
            (Ok(_), Err(e)) => {
                Some(DifferenceType::OkErr(e.clone()))
            }
            (Err(e), Ok(_)) => {
                Some(DifferenceType::ErrOk(e.clone()))
            }
            (Err(e1), Err(e2)) => {
                Some(DifferenceType::ErrErr(e1.clone(), e2.clone()))
            }
        };

        if let Some(difftype) = difftype {
            if !self.diffs.iter().any(|d| d.diff_types == difftype) {
                self.diffs.push(Difference { diff_types: difftype, example_before: before.clone() });
            }
        }

        r1
    }

    fn scan_memory_accesses(&mut self, before: &SystemState<X64Arch>) -> Result<Vec<Addr>, OracleError> {
        self.o1.scan_memory_accesses(before)
    }

    fn debug_dump(&mut self) {
        println!("First:");
        self.o1.debug_dump();

        println!();
        println!("Second:");
        self.o2.debug_dump();
    }

    fn debug_dump_state(&mut self, state: &SystemState<X64Arch>) {
        println!("First:");
        self.o1.debug_dump_state(state);

        println!();
        println!("Second:");
        self.o2.debug_dump_state(state);
    }

    fn restart(&mut self) {
        self.o1.restart();
        self.o2.restart();
    }

    fn kill(self) {
        self.o1.kill();
        self.o2.kill();
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
