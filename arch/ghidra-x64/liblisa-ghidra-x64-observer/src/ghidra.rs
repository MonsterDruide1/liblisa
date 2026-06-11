use std::collections::HashMap;

use liblisa::arch::CpuState;
use liblisa::oracle::OracleError;
use liblisa::state;
use liblisa::state::Addr;
use liblisa::arch::x64::{Align32, GpReg, X64Arch, X64State, X87, Xmm};

use crate::bind;

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

pub fn ghidra_to_liblisa(state: &bind::SystemState, memory_before: &state::MemoryState) -> state::SystemState<X64Arch> {
    let memory_data: HashMap<u64, Vec<u8>> = unsafe {
        std::slice::from_raw_parts(state.memory.entries, state.memory.num_entries as usize).iter().map(|entry| {
            (entry.address, std::slice::from_raw_parts(entry.data, entry.size as usize).to_vec())
        })
    }.collect();
    
    let memory = memory_before.iter().enumerate().map(|(index, (addr, perms, old_data))| {
        let offset = (addr.as_u64() & 0b1111_1111_1111) as usize;
        let page = addr.as_u64() & !0b1111_1111_1111;
        let page_data = memory_data.get(&page).unwrap_or_else(|| panic!("Ghidra did not return memory for page {:#x}, required for offset {:#x}", page, addr.as_u64()));
        // NOTE: defaults permissions to `ReadWrite`, as Ghidra's emulator has no permission system
        (*addr, state::Permissions::ReadWrite, page_data[offset..offset + old_data.len()].to_vec())
    });

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
            memory
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
            let observation_result = bind::observe(ghidra_state, self.instance);
            match observation_result.exception.exception_type {
                bind::ExceptionType_None => {},
                bind::ExceptionType_PageFault => return Err(OracleError::MemoryAccess(Addr::new(observation_result.exception.address))),
                bind::ExceptionType_InstructionPageFault => return Err(OracleError::InstructionFetchMemoryAccess(Addr::new(observation_result.exception.address))),
                bind::ExceptionType_InvalidInstruction => return Err(OracleError::InvalidInstruction),
                exception => unreachable!("Ghidra emulator threw unexpected exception: {:?}", exception),
            }
            let new_state = *observation_result.after;
            let result = ghidra_to_liblisa(&new_state, before.memory());
            bind::cleanup_systemstate(observation_result);
            Ok(result)
        }
    }

    pub fn scan_memory_accesses(&mut self, before: &state::SystemState<X64Arch>) -> Result<Vec<Addr>, OracleError> {
        unsafe {
            let ghidra_state = liblisa_to_ghidra(before);
            let scan_result = bind::scan_memory_accesses(ghidra_state, self.instance);
            match scan_result.exception.exception_type {
                bind::ExceptionType_None => {},
                bind::ExceptionType_PageFault => return Err(OracleError::MemoryAccess(Addr::new(scan_result.exception.address))),
                bind::ExceptionType_InstructionPageFault => return Err(OracleError::InstructionFetchMemoryAccess(Addr::new(scan_result.exception.address))),
                bind::ExceptionType_InvalidInstruction => return Err(OracleError::InvalidInstruction),
                exception => unreachable!("Ghidra emulator threw unexpected exception during memory access scan: {:?}", exception),
            }
            let accesses = *scan_result.accesses;
            let result = (0..accesses.num_accesses).map(|index| Addr::new(*accesses.accesses.offset(index as isize))).collect();
            bind::cleanup_memoryaccesses(scan_result);
            Ok(result)
        }
    }

    pub fn debug_dump(&mut self) {
        unsafe {
            bind::debug_dump(self.instance);
        }
    }

    pub fn debug_dump_pcode(&mut self, instruction: &[u8]) {
        unsafe {
            bind::debug_dump_pcode(self.instance, instruction.as_ptr());
        }
    }

    pub fn debug_dump_state(&mut self, state: &state::SystemState<X64Arch>) {
        let pc = CpuState::<X64Arch>::gpreg(state.cpu(), GpReg::Rip);
        let instruction = state.memory().iter().find_map(|(addr, _, data)| {
            let offset = pc.checked_sub(addr.as_u64())?;
            if (offset as usize) < data.len() {
                Some(&data[offset as usize..])
            } else {
                None
            }
        }).unwrap_or(&[]);
        
        println!("{:#?}", state);
        unsafe {
            bind::debug_dump_pcode(self.instance, instruction.as_ptr());
        }
    }
}
