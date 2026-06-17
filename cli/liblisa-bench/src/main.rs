use liblisa_ghidra_x64_observer::GhidraOracle;
use liblisa_x64_observer::VmOracleSource;
use liblisa::oracle::{Oracle, OracleSource};
use liblisa::state::{Addr, Permissions, SystemState, MemoryState};
use liblisa::arch::x64::{GpReg, X64State, X64Arch};

fn bench<T: Oracle<X64Arch>>(mut o: T, state: &SystemState<X64Arch>, iterations: usize) {
    let time_before = std::time::Instant::now();
    for _ in 0..iterations {
        let _ = o.observe(state);
    }
    let time_after = std::time::Instant::now();
    println!("Single-Result: took {:?}, {:?} Hz", time_after - time_before, iterations as f64 / (time_after - time_before).as_secs_f64());
    let time_before = std::time::Instant::now();
    for _ in 0..(iterations/1000) {
        let _ = o.batch_observe([state; 1000]);
    }
    let time_after = std::time::Instant::now();
    println!("Batch-Result: took {:?}, {:?} Hz", time_after - time_before, iterations as f64 / (time_after - time_before).as_secs_f64());
}

pub fn main() {
    env_logger::init();
    
    let iterations = 100000;
    
    let mut state = SystemState::<X64Arch> {
        cpu: Box::new(X64State::default()),
        memory: MemoryState::default(),
        contains_valid_addrs: true,
        use_trap_flag: false,
    };
    state.cpu_mut().regs[GpReg::Rip as usize] = 0xFFFFFFFFFFFFFFFE;
    state.memory_mut().data = vec![
        (Addr::new(0xFFFFFFFFFFFFFFFE), Permissions::Execute, vec![0x31, 0x00]),
        (Addr::new(0), Permissions::ReadWrite, vec![0x00; 8]),
    ].into_boxed_slice();

    println!("Testing GhidraOracle...");
    bench(GhidraOracle::new(), &state, iterations);

    println!("Testing VmOracle...");
    bench(VmOracleSource::new(None, 2).start().pop().unwrap(), &state, iterations);
}
