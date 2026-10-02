use liblisa::arch::{CpuState, x64::{GpReg, X64Arch, X64Flag, X87Reg, XmmReg}};
use liblisa::state::SystemState;
use thiserror::Error;
use xed_sys::*;
use log::error;

#[derive(Error, Debug)]
pub enum XedError {
    #[error("XED decode error: {0}")]
    DecodeError(String),
}

pub struct XedInterface {
    inst: xed_decoded_inst_t,
}

#[derive(Debug, Clone, PartialEq)]
pub enum InstrOperandReg {
    GpReg {
        reg: GpReg,
        width: u8,  // in bytes
        offset: u8,  // in bytes
    },
    XmmReg(XmmReg),
    X87Reg(X87Reg),
    SReg(&'static str),
    X87Status,
    X87Control,
    StackPush,
    ControlReg(u8),
    Unk,
}

#[derive(Debug, Clone, PartialEq)]
pub enum InstrOperand {
    Reg(InstrOperandReg),
    Mem {
        access: MemAccess,
        seg: Option<GpReg>,
        base: Option<GpReg>,
        index: Option<GpReg>,
        scale: u8,
        disp: Option<i64>,
        width: u32,
    },
    ImmSigned(i32),
    ImmUnsigned(u64),
    SecondImm(u8),
    Unk,
}
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MemAccess: u8 {
        const READ  = 0b01;
        const WRITE = 0b10;
    }
}

impl InstrOperand {
    fn get_width_mask(width: u8) -> u64 {
        match width {
            1 => 0xff,
            2 => 0xffff,
            4 => 0xffffffff,
            8 => 0xffffffffffffffff,
            _ => panic!("Unsupported width: {}", width),
        }
    }

    pub fn is_reg(&self, reg: &GpReg) -> bool {
        match self {
            InstrOperand::Reg(InstrOperandReg::GpReg { reg: r, .. }) => r == reg,
            _ => false,
        }
    }
    pub fn is_x87_reg(&self, reg: &X87Reg) -> bool {
        match self {
            InstrOperand::Reg(InstrOperandReg::X87Reg(r)) => r == reg,
            _ => false,
        }
    }
    pub fn is_xmm_reg(&self, reg: &XmmReg) -> bool {
        match self {
            InstrOperand::Reg(InstrOperandReg::XmmReg(r)) => r == reg,
            _ => false,
        }
    }
    pub fn get_reg_value(&self, state: &SystemState<X64Arch>) -> Option<u64> {
        match self {
            InstrOperand::Reg(InstrOperandReg::GpReg { reg, width, offset }) => {
                let value = CpuState::<X64Arch>::gpreg(state.cpu(), *reg);
                Some((value >> (offset * 8)) & Self::get_width_mask(*width))
            }
            _ => None,
        }
    }
}

pub unsafe fn c2s(ptr: *const i8) -> String {
    let cstr = std::ffi::CStr::from_ptr(ptr);
    cstr.to_string_lossy().into_owned()
}

impl XedInterface {
    unsafe fn init() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            xed_tables_init();
        });
        
    }
    pub unsafe fn new(data: &[u8]) -> Result<Self, XedError> {
        Self::init();

        let mut inst = std::mem::MaybeUninit::<xed_decoded_inst_t>::uninit();
        xed_decoded_inst_zero(inst.as_mut_ptr());
        xed_decoded_inst_set_mode(inst.as_mut_ptr(), XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
        let xed_error: xed_error_enum_t = xed_decode(inst.as_mut_ptr(), data.as_ptr(), data.len() as u32);
        if xed_error != XED_ERROR_NONE {
            return Err(XedError::DecodeError(c2s(xed_error_enum_t2str(xed_error))));
        }
        Ok(Self {
            inst: inst.assume_init(),
        })
    }

    pub unsafe fn get_iclass(&self) -> String {
        return c2s(xed_iclass_enum_t2str(xed_decoded_inst_get_iclass(&self.inst)));
    }

    pub unsafe fn get_undefined_flags(&self) -> Vec<X64Flag> {
        let rflags_info = xed_decoded_inst_get_rflags_info(&self.inst);
        let undef_flags = xed_simple_flag_get_undefined_flag_set(rflags_info);
        let mut flags = Vec::new();
        if (*undef_flags).s.cf() != 0 {
            flags.push(X64Flag::Cf);
        }
        if (*undef_flags).s.pf() != 0 {
            flags.push(X64Flag::Pf);
        }
        if (*undef_flags).s.af() != 0 {
            flags.push(X64Flag::Af);
        }
        if (*undef_flags).s.zf() != 0 {
            flags.push(X64Flag::Zf);
        }
        if (*undef_flags).s.sf() != 0 {
            flags.push(X64Flag::Sf);
        }
        if (*undef_flags).s.of() != 0 {
            flags.push(X64Flag::Of);
        }
        flags
    }

    pub unsafe fn is_rexx(&self) -> bool {
        xed3_operand_get_rexx(&self.inst) != 0
    }

    // note: this function is very specific to the current use case
    // and might be generalized in the future
    pub unsafe fn get_operands(&self) -> Vec<InstrOperand> {
        let xi = xed_decoded_inst_inst(&self.inst);
        let mut operands = Vec::new();
        for i in 0..xed_inst_noperands(xi) {
            let operand_name: xed_operand_enum_t = xed_operand_name(xed_inst_operand(xi, i));
            let operand = match operand_name {
                XED_OPERAND_REG0 | XED_OPERAND_REG1 | XED_OPERAND_REG2 | XED_OPERAND_REG3 | XED_OPERAND_REG4 | XED_OPERAND_REG5 | XED_OPERAND_REG6 | XED_OPERAND_REG7 => {
                    let reg = Self::xed_reg_to_opreg(xed_decoded_inst_get_reg(&self.inst, operand_name));
                    InstrOperand::Reg(reg)
                },
                XED_OPERAND_IMM0 => {
                    if xed_decoded_inst_get_immediate_is_signed(&self.inst) != 0 {
                        let imm = xed_decoded_inst_get_signed_immediate(&self.inst);
                        InstrOperand::ImmSigned(imm)
                    } else {
                        let imm = xed_decoded_inst_get_unsigned_immediate(&self.inst);
                        InstrOperand::ImmUnsigned(imm)
                    }
                },
                XED_OPERAND_IMM1 => {
                    // second immediate is always 1 byte, unsigned
                    InstrOperand::SecondImm(xed_decoded_inst_get_second_immediate(&self.inst))
                },
                XED_OPERAND_MEM0 | XED_OPERAND_MEM1 => {
                    let mem_idx = if operand_name == XED_OPERAND_MEM0 { 0 } else { 1 };
                    let mut access = MemAccess::empty();
                    if xed_decoded_inst_mem_read(&self.inst, mem_idx) != 0 {
                        access |= MemAccess::READ;
                    }
                    if xed_decoded_inst_mem_written(&self.inst, mem_idx) != 0 {
                        access |= MemAccess::WRITE;
                    }
                    let x2g = |x| {
                        if x == XED_REG_INVALID {
                            return None;
                        }
                        match Self::xed_reg_to_opreg(x) {
                            InstrOperandReg::GpReg { reg: g, .. } => Some(g),
                            _ => panic!("Unexpected register type: {:?}", x),
                        }
                    };
                    let seg = x2g(xed_decoded_inst_get_seg_reg(&self.inst, mem_idx));
                    let base = x2g(xed_decoded_inst_get_base_reg(&self.inst, mem_idx));
                    let index = x2g(xed_decoded_inst_get_index_reg(&self.inst, mem_idx));
                    let scale = xed_decoded_inst_get_scale(&self.inst, mem_idx) as u8;
                    let disp = if xed_operand_values_has_memory_displacement(&self.inst) != 0 {
                        Some(xed_decoded_inst_get_memory_displacement(&self.inst, mem_idx))
                    } else { None };
                    let width = xed_decoded_inst_get_memory_operand_length(&self.inst,mem_idx);

                    InstrOperand::Mem { access, seg, base, index, scale, disp, width }
                },
                _ => InstrOperand::Unk,
            };
            operands.push(operand);
        }
        operands
    }

    pub unsafe fn is_operand_sreg(&self, index: u32) -> bool {
        let xi = xed_decoded_inst_inst(&self.inst);
        if index >= xed_inst_noperands(xi) { return false; }
        let operand_name: xed_operand_enum_t = xed_operand_name(xed_inst_operand(xi, index));
        if !matches!(operand_name, XED_OPERAND_REG0 | XED_OPERAND_REG1 | XED_OPERAND_REG2 | XED_OPERAND_REG3 | XED_OPERAND_REG4 | XED_OPERAND_REG5 | XED_OPERAND_REG6 | XED_OPERAND_REG7) {
            return false;
        }
        let reg = xed_decoded_inst_get_reg(&self.inst, operand_name);
        matches!(reg, XED_REG_ES | XED_REG_CS | XED_REG_SS | XED_REG_DS | XED_REG_FS | XED_REG_GS)
    }

    unsafe fn xed_reg_to_opreg(reg: xed_reg_enum_t) -> InstrOperandReg {
        let enclosing_gpreg = match xed_get_largest_enclosing_register(reg) {
            XED_REG_RAX => Some(GpReg::Rax),
            XED_REG_RCX => Some(GpReg::Rcx),
            XED_REG_RDX => Some(GpReg::Rdx),
            XED_REG_RSI => Some(GpReg::Rsi),
            XED_REG_RDI => Some(GpReg::Rdi),
            XED_REG_RIP => Some(GpReg::Rip),
            XED_REG_RBP => Some(GpReg::Rbp),
            XED_REG_RBX => Some(GpReg::Rbx),
            XED_REG_RSP => Some(GpReg::Rsp),
            XED_REG_R8 => Some(GpReg::R8),
            XED_REG_R9 => Some(GpReg::R9),
            XED_REG_R10 => Some(GpReg::R10),
            XED_REG_R11 => Some(GpReg::R11),
            XED_REG_R12 => Some(GpReg::R12),
            XED_REG_R13 => Some(GpReg::R13),
            XED_REG_R14 => Some(GpReg::R14),
            XED_REG_R15 => Some(GpReg::R15),
            XED_REG_FSBASE => Some(GpReg::FsBase),
            XED_REG_GSBASE => Some(GpReg::GsBase),
            XED_REG_RFLAGS => Some(GpReg::RFlags),
            _ => None,
        };
        if let Some(gpreg) = enclosing_gpreg {
            let width = xed_get_register_width_bits64(reg) / 8;
            let offset = match reg {
                XED_REG_AH | XED_REG_CH | XED_REG_DH | XED_REG_BH => 1,
                _ => 0,
            };
            return InstrOperandReg::GpReg { reg: gpreg, width: width as u8, offset: offset as u8 };
        }

        match reg {
            XED_REG_MMX0 | XED_REG_ST0 => InstrOperandReg::X87Reg(X87Reg::Fpr(0)),
            XED_REG_MMX1 | XED_REG_ST1 => InstrOperandReg::X87Reg(X87Reg::Fpr(1)),
            XED_REG_MMX2 | XED_REG_ST2 => InstrOperandReg::X87Reg(X87Reg::Fpr(2)),
            XED_REG_MMX3 | XED_REG_ST3 => InstrOperandReg::X87Reg(X87Reg::Fpr(3)),
            XED_REG_MMX4 | XED_REG_ST4 => InstrOperandReg::X87Reg(X87Reg::Fpr(4)),
            XED_REG_MMX5 | XED_REG_ST5 => InstrOperandReg::X87Reg(X87Reg::Fpr(5)),
            XED_REG_MMX6 | XED_REG_ST6 => InstrOperandReg::X87Reg(X87Reg::Fpr(6)),
            XED_REG_MMX7 | XED_REG_ST7 => InstrOperandReg::X87Reg(X87Reg::Fpr(7)),

            XED_REG_XMM0 => InstrOperandReg::XmmReg(XmmReg::Reg(0)),
            XED_REG_XMM1 => InstrOperandReg::XmmReg(XmmReg::Reg(1)),
            XED_REG_XMM2 => InstrOperandReg::XmmReg(XmmReg::Reg(2)),
            XED_REG_XMM3 => InstrOperandReg::XmmReg(XmmReg::Reg(3)),
            XED_REG_XMM4 => InstrOperandReg::XmmReg(XmmReg::Reg(4)),
            XED_REG_XMM5 => InstrOperandReg::XmmReg(XmmReg::Reg(5)),
            XED_REG_XMM6 => InstrOperandReg::XmmReg(XmmReg::Reg(6)),
            XED_REG_XMM7 => InstrOperandReg::XmmReg(XmmReg::Reg(7)),
            XED_REG_XMM8 => InstrOperandReg::XmmReg(XmmReg::Reg(8)),
            XED_REG_XMM9 => InstrOperandReg::XmmReg(XmmReg::Reg(9)),
            XED_REG_XMM10 => InstrOperandReg::XmmReg(XmmReg::Reg(10)),
            XED_REG_XMM11 => InstrOperandReg::XmmReg(XmmReg::Reg(11)),
            XED_REG_XMM12 => InstrOperandReg::XmmReg(XmmReg::Reg(12)),
            XED_REG_XMM13 => InstrOperandReg::XmmReg(XmmReg::Reg(13)),
            XED_REG_XMM14 => InstrOperandReg::XmmReg(XmmReg::Reg(14)),
            XED_REG_XMM15 => InstrOperandReg::XmmReg(XmmReg::Reg(15)),

            XED_REG_ES => InstrOperandReg::SReg("ES"),
            XED_REG_CS => InstrOperandReg::SReg("CS"),
            XED_REG_SS => InstrOperandReg::SReg("SS"),
            XED_REG_DS => InstrOperandReg::SReg("DS"),
            XED_REG_FS => InstrOperandReg::SReg("FS"),
            XED_REG_GS => InstrOperandReg::SReg("GS"),

            XED_REG_STACKPUSH => InstrOperandReg::StackPush,
            XED_REG_X87CONTROL => InstrOperandReg::X87Control,
            XED_REG_X87STATUS => InstrOperandReg::X87Status,
            XED_REG_X87TAG => InstrOperandReg::X87Reg(X87Reg::TagWord),

            XED_REG_CR0 => InstrOperandReg::ControlReg(0),
            XED_REG_CR1 => InstrOperandReg::ControlReg(1),
            XED_REG_CR2 => InstrOperandReg::ControlReg(2),
            XED_REG_CR3 => InstrOperandReg::ControlReg(3),
            XED_REG_CR4 => InstrOperandReg::ControlReg(4),
            XED_REG_CR5 => InstrOperandReg::ControlReg(5),
            XED_REG_CR6 => InstrOperandReg::ControlReg(6),
            XED_REG_CR7 => InstrOperandReg::ControlReg(7),
            XED_REG_CR8 => InstrOperandReg::ControlReg(8),
            XED_REG_CR9 => InstrOperandReg::ControlReg(9),
            XED_REG_CR10 => InstrOperandReg::ControlReg(10),
            XED_REG_CR11 => InstrOperandReg::ControlReg(11),
            XED_REG_CR12 => InstrOperandReg::ControlReg(12),
            XED_REG_CR13 => InstrOperandReg::ControlReg(13),
            XED_REG_CR14 => InstrOperandReg::ControlReg(14),
            XED_REG_CR15 => InstrOperandReg::ControlReg(15),

            _ => {
                error!("XED register {:?} not mapped to OpReg", reg);
                InstrOperandReg::Unk
            }
        }
    }
}
