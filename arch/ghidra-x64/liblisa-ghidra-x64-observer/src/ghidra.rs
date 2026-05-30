use liblisa::arch::x64::X64Arch;
use liblisa::oracle::OracleError;
use liblisa::state::{Addr, SystemState};

#[derive(Debug)]
pub struct GhidraObserver {
    
}
impl GhidraObserver {
    pub fn new() -> Self {
        Self {}
    }

    pub fn observe(&mut self, before: &SystemState<X64Arch>) -> Result<SystemState<X64Arch>, OracleError> {
        unimplemented!()
    }

    pub fn scan_memory_accesses(&mut self, before: &SystemState<X64Arch>) -> Result<Vec<Addr>, OracleError> {
        unimplemented!()
    }

    pub fn debug_dump(&mut self) {
        unimplemented!()
    }
}
