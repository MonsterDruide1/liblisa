use std::collections::HashMap;
use log::warn;

use liblisa::arch::CpuState;
use liblisa::oracle::OracleError;
use liblisa::state;
use liblisa::state::Addr;
use liblisa::arch::x64::{Align32, GpReg, X64Arch, X64Flag, X64State, X87, Xmm};

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

struct SystemStateWithMemory {
    state: bind::SystemState,
    memory_data: Vec<Vec<u8>>,
    memory_entries: Vec<bind::MemoryEntry>,
}

// also returns memory data (Vec<Vec<u8>>) and memory entries (Vec<bind::MemoryEntry>) to keep them alive while the pointers in `bind::SystemState` are still used
pub fn liblisa_to_ghidra<'a>(state: &state::SystemState<X64Arch>) -> SystemStateWithMemory {
    let mut memory_data = Vec::new();
    let mut memory_entries = Vec::new();

    for (_, _, data) in state.memory().iter() {
        memory_data.push(data.clone());
    }
    for (i, (addr, perms, _)) in state.memory().iter().enumerate() {
        let data = &memory_data[i];
        memory_entries.push(bind::MemoryEntry {
            address: addr.as_u64(),
            size: data.len() as u64,
            data: data.as_ptr() as *mut u8,
            permissions: match perms {
                state::Permissions::Read => bind::Permission_Permission_Read,
                state::Permissions::ReadWrite => bind::Permission_Permission_Read | bind::Permission_Permission_Write,
                state::Permissions::Execute => bind::Permission_Permission_Read | bind::Permission_Permission_Execute,
            },
        });
    }

    let mut regs = state.cpu().regs.0;
    const TRAP_FLAG: u64 = 1 << 8;
    regs[GpReg::RFlags as usize] = ((CpuState::<X64Arch>::flag(state.cpu(), X64Flag::Cf) as u64)
            | ((CpuState::<X64Arch>::flag(state.cpu(), X64Flag::Pf) as u64) << 2)
            | ((CpuState::<X64Arch>::flag(state.cpu(), X64Flag::Af) as u64) << 4)
            | ((CpuState::<X64Arch>::flag(state.cpu(), X64Flag::Zf) as u64) << 6)
            | ((CpuState::<X64Arch>::flag(state.cpu(), X64Flag::Sf) as u64) << 7)
            | ((CpuState::<X64Arch>::flag(state.cpu(), X64Flag::Of) as u64) << 11))
            | if state.use_trap_flag { TRAP_FLAG } else { 0 };

    let state = bind::SystemState {
        cpu: bind::X64State {
            regs: regs,
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

    SystemStateWithMemory { state, memory_data, memory_entries }
}

pub fn ghidra_to_liblisa(state: &bind::SystemState, memory_before: &state::MemoryState) -> state::SystemState<X64Arch> {
    let memory_data: HashMap<u64, (Vec<u8>, state::Permissions)> = unsafe {
        std::slice::from_raw_parts(state.memory.entries, state.memory.num_entries as usize).iter().map(|entry| {
            let is_read = entry.permissions & bind::Permission_Permission_Read != 0;
            let is_write = entry.permissions & bind::Permission_Permission_Write != 0;
            let is_execute = entry.permissions & bind::Permission_Permission_Execute != 0;
            let perms =
                if is_read && !is_write && !is_execute {
                    state::Permissions::Read
                } else if is_read && is_write && !is_execute {
                    state::Permissions::ReadWrite
                } else if is_read && !is_write && is_execute {
                    state::Permissions::Execute
                } else {
                    unreachable!("Ghidra returned memory entry with invalid permissions: {:#x}", entry.permissions);
                };
            (entry.address, (std::slice::from_raw_parts(entry.data, entry.size as usize).to_vec(), perms))
        })
    }.collect();
    
    let memory = memory_before.iter().enumerate().map(|(index, (addr, perms, old_data))| {
        let (new_data, new_perms) = memory_data.get(&addr.as_u64()).unwrap_or_else(|| panic!("Ghidra did not return memory for address {:#x}", addr.as_u64() & !0b1111_1111_1111));
        if *perms != *new_perms {
            warn!("Ghidra returned different permissions for page {:#x} than provided by liblisa: {:#?} vs {:#?}", addr.as_u64() & !0b1111_1111_1111, perms, new_perms);
        }
        (*addr, *perms, new_data.clone())
    });

    let mut result = state::SystemState::new(
        X64State {
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
        },
        state::MemoryState::new(
            memory
        ),
    );

    let rflags = state.cpu.regs[GpReg::RFlags as usize];
    let cpu: &mut X64State = result.cpu_mut();
    cpu.regs.0[GpReg::RFlags as usize] = 0;
    CpuState::<X64Arch>::set_flag(cpu, X64Flag::Cf, rflags & 1 == 1);
    CpuState::<X64Arch>::set_flag(cpu, X64Flag::Pf, (rflags >> 2) & 1 == 1);
    CpuState::<X64Arch>::set_flag(cpu, X64Flag::Af, (rflags >> 4) & 1 == 1);
    CpuState::<X64Arch>::set_flag(cpu, X64Flag::Zf, (rflags >> 6) & 1 == 1);
    CpuState::<X64Arch>::set_flag(cpu, X64Flag::Sf, (rflags >> 7) & 1 == 1);
    CpuState::<X64Arch>::set_flag(cpu, X64Flag::Of, (rflags >> 11) & 1 == 1);

    result
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
            let observation_result = bind::observe(ghidra_state.state, self.instance);
            match observation_result.exception.exception_type {
                bind::ExceptionType_None => {},
                bind::ExceptionType_PageFault => return Err(OracleError::MemoryAccess(Addr::new(observation_result.exception.address))),
                bind::ExceptionType_InstructionPageFault => return Err(OracleError::InstructionFetchMemoryAccess(Addr::new(observation_result.exception.address))),
                bind::ExceptionType_InvalidInstruction => return Err(OracleError::InvalidInstruction),
                bind::ExceptionType_ComputationError => return Err(OracleError::ComputationError),
                bind::ExceptionType_GeneralProtectionFault => return Err(OracleError::GeneralFault),
                bind::ExceptionType_CustomPcodeOpCalled => return Err(OracleError::ApiError("Ghidra emulator called a custom pcode op".to_string())),
                bind::ExceptionType_VarnodeTooLarge => return Err(OracleError::ApiError("Ghidra emulator reported varnode too large".to_string())),
                bind::ExceptionType_EmulationUnimplemented => return Err(OracleError::ApiError("Ghidra emulator reported emulation unimplemented".to_string())),
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
            let scan_result = bind::scan_memory_accesses(ghidra_state.state, self.instance);
            match scan_result.exception.exception_type {
                bind::ExceptionType_None => {},
                bind::ExceptionType_PageFault => return Err(OracleError::MemoryAccess(Addr::new(scan_result.exception.address))),
                bind::ExceptionType_InstructionPageFault => return Err(OracleError::InstructionFetchMemoryAccess(Addr::new(scan_result.exception.address))),
                bind::ExceptionType_InvalidInstruction => return Err(OracleError::InvalidInstruction),
                bind::ExceptionType_ComputationError => return Err(OracleError::ComputationError),
                bind::ExceptionType_GeneralProtectionFault => return Err(OracleError::GeneralFault),
                bind::ExceptionType_CustomPcodeOpCalled => return Err(OracleError::ApiError("Ghidra emulator called a custom pcode op".to_string())),
                bind::ExceptionType_VarnodeTooLarge => return Err(OracleError::ApiError("Ghidra emulator reported varnode too large".to_string())),
                bind::ExceptionType_EmulationUnimplemented => return Err(OracleError::ApiError("Ghidra emulator reported emulation unimplemented".to_string())),
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
