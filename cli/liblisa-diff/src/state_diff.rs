use liblisa::arch::{Arch, CpuState, Register};
use liblisa::arch::x64::{GpReg, X64Arch, X64Flag, X87, Xmm};
use liblisa::oracle::OracleError;
use liblisa::state::LocationKind::Memory;
use liblisa::state::{Addr, SystemState};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Difference {
    pub diff_type: DifferenceType,
    pub example_before: SystemState<X64Arch>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum DifferenceType {
    OkOk(Vec<OkMismatch>),
    OkErr(OracleError),
    ErrOk(OracleError),
    ErrErr(OracleError, OracleError),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum OkMismatch {
    // CPU State
    RegMismatch(GpReg, u64, u64),
    FlagsMismatch(X64Flag, bool, bool),
    XmmMismatch(Xmm, Xmm),
    X87Mismatch(X87, X87),
    XmmExceptionFlagsMismatch(u64, u64),
    XmmDazMismatch(u8, u8),
    // Mem State
    MemoryMismatch(Addr, Vec<u8>, Vec<u8>),
}

impl DifferenceType {
    /// checks whether other is a subset of self (i.e. all differences in other are also present in self)
    pub fn contains(&self, other: &Self) -> bool {
        use DifferenceType::*;
        match (self, other) {
            (OkOk(m1), OkOk(m2)) => m2.iter().all(|m| m1.contains(m)),
            (OkErr(e1), OkErr(e2)) => e1 == e2,
            (ErrOk(e1), ErrOk(e2)) => e1 == e2,
            (ErrErr(e1a, e1b), ErrErr(e2a, e2b)) => e1a == e2a && e1b == e2b,
            _ => false,
        }
    }
}

impl PartialEq for OkMismatch {
    fn eq(&self, other: &Self) -> bool {
        use OkMismatch::*;
        match (self, other) {
            // special case: memory changes are always considered equal
            (MemoryMismatch(_, _, _), MemoryMismatch(_, _, _)) => true,
            // special cases: consider location of mismatch, ignore values
            (RegMismatch(r1, _, _), RegMismatch(r2, _, _)) => r1 == r2,
            (FlagsMismatch(f1, _, _), FlagsMismatch(f2, _, _)) => f1 == f2,

            // standard cases: consider everything about mismatch
            (XmmMismatch(x1, x2), XmmMismatch(y1, y2)) => x1 == y1 && x2 == y2,
            (X87Mismatch(x1, x2), X87Mismatch(y1, y2)) => x1 == y1 && x2 == y2,
            (XmmExceptionFlagsMismatch(f1, f2), XmmExceptionFlagsMismatch(g1, g2)) => f1 == g1 && f2 == g2,
            (XmmDazMismatch(d1, d2), XmmDazMismatch(e1, e2)) => d1 == e1 && d2 == e2,
            // all other combinations are not equal
            _ => false,
        }
    }
}

pub fn compare(r1: &Result<SystemState<X64Arch>, OracleError>, r2: &Result<SystemState<X64Arch>, OracleError>) -> Option<DifferenceType> {
    use OracleError::*;
    match (&r1, &r2) {
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
                if reg.is_flags() {
                    continue;
                }
                let v1 = CpuState::<X64Arch>::gpreg(r1.cpu(), reg);
                let v2 = CpuState::<X64Arch>::gpreg(r2.cpu(), reg);
                if v1 != v2 {
                    mismatches.push(OkMismatch::RegMismatch(reg, v1, v2));
                }
            }
            // 6 flags exist in `flagreg_to_flags` of RFlags
            for flag in X64Arch::flagreg_to_flags(X64Arch::reg(GpReg::RFlags), 0, 5) {
                let v1 = CpuState::<X64Arch>::flag(r1.cpu(), *flag);
                let v2 = CpuState::<X64Arch>::flag(r2.cpu(), *flag);
                if v1 != v2 {
                    mismatches.push(OkMismatch::FlagsMismatch(*flag, v1, v2));
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
    }
}
