use liblisa::arch::x64::X64Arch;
use liblisa::oracle::OracleError;
use liblisa::state;
use liblisa::state::Addr;
use liblisa::arch::x64::{Align32, X64State, Xmm, X87};

use crate::bind;

use libc::malloc_usable_size;

fn bits_to_bytes<const N: usize>(bits: u8) -> u64 {
    assert!(N > 0 && N <= 8);

    (0..N)
        .map(|index| (bits as u64 & (1 << index)) << (7 * index))
        .reduce(|a, b| a | b)
        .unwrap()
}

fn bytes_to_bits<const N: usize>(bytes: u64) -> u8 {
    assert!(N > 0 && N <= 8);

    (0..N)
        .map(|index| ((bytes & (1 << (8 * index))) >> (7 * index)) as u8)
        .reduce(|a, b| a | b)
        .unwrap()
}

// also returns memory data (Vec<Vec<u8>>) and memory entries (Vec<bind::MemoryEntry>) to keep them alive while the pointers in `bind::SystemState` are still used
pub fn liblisa_to_ghidra(state: &state::SystemState<X64Arch>) -> bind::SystemState {
    let mut memory_data = Vec::new();
    let mut memory_entries = Vec::new();
    
    // NOTE: ignores permissions, as Ghidra has no permission system
    for (_, _, data) in state.memory().iter() {
        memory_data.push(data.clone());
    }
    for (i, (addr, _, _)) in state.memory().iter().enumerate() {
        let data = &memory_data[i];
        memory_entries.push(bind::MemoryEntry {
            address: addr.as_u64(),
            size: data.len() as u64,
            data: data.as_ptr() as *mut u8,
        });
    }

    let state = bind::SystemState {
        cpu: bind::X64State {
            regs: state.cpu().regs.0,
            xmm: bind::Xmm {
                regs: state.cpu().xmm.regs.0,
            },
            x87: bind::X87 {
                fpr: state.cpu().x87.fpr,
                top_of_stack: state.cpu().x87.top_of_stack,
                exception_flags: bytes_to_bits::<8>(state.cpu().x87.exception_flags),
                condition_codes: bytes_to_bits::<4>(state.cpu().x87.condition_codes as u64),
                tag_word: state.cpu().x87.tag_word,
            },
            xmm_exception_flags: bytes_to_bits::<6>(state.cpu().xmm_exception_flags),
            xmm_daz: state.cpu().xmm_daz,
        },
        memory: bind::MemoryState {
            num_entries: state.memory().len() as u32,
            entries: memory_entries.as_mut_ptr(),
        },
        use_trap_flag: state.use_trap_flag,
        contains_valid_addrs: state.contains_valid_addrs,
    };
    
    std::mem::forget(memory_data);
    std::mem::forget(memory_entries);

    state
}

pub fn ghidra_to_liblisa(state: &bind::SystemState) -> state::SystemState<X64Arch> {
    state::SystemState {
        cpu: Box::new(X64State {
            regs: Align32(state.cpu.regs),
            xmm: Xmm {
                regs: Align32(state.cpu.xmm.regs),
            },
            x87: X87 {
                fpr: state.cpu.x87.fpr,
                top_of_stack: state.cpu.x87.top_of_stack,
                exception_flags: bits_to_bytes::<8>(state.cpu.x87.exception_flags),
                condition_codes: bits_to_bytes::<4>(state.cpu.x87.condition_codes) as u32,
                tag_word: state.cpu.x87.tag_word,
            },
            xmm_exception_flags: bits_to_bytes::<6>(state.cpu.xmm_exception_flags),
            xmm_daz: state.cpu.xmm_daz,
        }),
        memory: state::MemoryState::new(
            unsafe {
                std::slice::from_raw_parts(state.memory.entries, state.memory.num_entries as usize).iter().map(|entry| {
                    // NOTE: defaults permissions to `ReadWrite`, as Ghidra's emulator has no permission system
                    (Addr::new(entry.address), state::Permissions::ReadWrite, std::slice::from_raw_parts(entry.data, entry.size as usize).to_vec())
                })
            }
        ),
        use_trap_flag: state.use_trap_flag,
        contains_valid_addrs: state.contains_valid_addrs,
    }
}

#[derive(Debug)]
pub struct GhidraObserver {
    instance: *mut bind::EmulatorInstance,
}
unsafe impl Send for GhidraObserver {}
impl GhidraObserver {
    pub fn new() -> Self {
        unsafe {
            let instance = bind::setup();
            Self { instance }
        }
    }

    pub fn observe(&mut self, before: &state::SystemState<X64Arch>) -> Result<state::SystemState<X64Arch>, OracleError> {
        unsafe {
            let ghidra_state = liblisa_to_ghidra(before);
            let new_state_ptr = bind::observe(ghidra_state, self.instance);
            let new_state = *new_state_ptr;
            let result = ghidra_to_liblisa(&new_state);
            bind::cleanup_systemstate(new_state_ptr);
            Ok(result)
        }
    }

    pub fn scan_memory_accesses(&mut self, before: &state::SystemState<X64Arch>) -> Result<Vec<Addr>, OracleError> {
        unsafe {
            let ghidra_state = liblisa_to_ghidra(before);
            let accesses_ptr = bind::scan_memory_accesses(ghidra_state, self.instance);
            let accesses = *accesses_ptr;
            let result = (0..accesses.num_accesses).map(|index| Addr::new(*accesses.accesses.offset(index as isize))).collect();
            bind::cleanup_memoryaccesses(accesses_ptr);
            Ok(result)
        }
    }

    pub fn debug_dump(&mut self) {
        unsafe {
            bind::debug_dump(self.instance);
        }
    }
}
