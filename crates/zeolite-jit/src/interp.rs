//! Reference interpreter for the IR.
//!
//! Runs on an explicit frame stack, so guest recursion never touches the native stack.
//! It defines the semantics that the JIT must reproduce exactly, and the differential
//! tests compare the two backends on randomly generated programs.

use crate::ir::{Inst, Program, Terminator};
use crate::syntax::{BinOp, UnOp, Width};
use crate::{Limits, Outcome, Trap};

pub(crate) fn eval_bin(op: BinOp, a: i64, b: i64) -> Result<i64, Trap> {
    Ok(match op {
        BinOp::Add => a.wrapping_add(b),
        BinOp::Sub => a.wrapping_sub(b),
        BinOp::Mul => a.wrapping_mul(b),
        BinOp::Div => {
            if b == 0 {
                return Err(Trap::DivideByZero);
            }
            if a == i64::MIN && b == -1 {
                return Err(Trap::IntegerOverflow);
            }
            a / b
        }
        BinOp::Rem => {
            if b == 0 {
                return Err(Trap::DivideByZero);
            }
            // The mathematical result is zero. Avoids the machine-level overflow trap.
            if b == -1 { 0 } else { a % b }
        }
        BinOp::And => a & b,
        BinOp::Or => a | b,
        BinOp::Xor => a ^ b,
        BinOp::Shl => a.wrapping_shl(b as u32),
        BinOp::Shr => a.wrapping_shr(b as u32),
        BinOp::ShrU => ((a as u64).wrapping_shr(b as u32)) as i64,
        BinOp::Eq => i64::from(a == b),
        BinOp::Ne => i64::from(a != b),
        BinOp::Lt => i64::from(a < b),
        BinOp::Le => i64::from(a <= b),
        BinOp::Gt => i64::from(a > b),
        BinOp::Ge => i64::from(a >= b),
    })
}

fn eval_un(op: UnOp, a: i64) -> i64 {
    match op {
        UnOp::Neg => a.wrapping_neg(),
        UnOp::Not => i64::from(a == 0),
        UnOp::BitNot => !a,
    }
}

/// Bounds check shared in meaning with the JIT: `limit` is `len - (width - 1)`, and an
/// address is valid when it is below `limit` as an unsigned value. `len >= 8` is
/// guaranteed by the public entry point.
fn checked_range(memory: &[u8], addr: i64, width: Width) -> Result<(usize, usize), Trap> {
    let limit = memory.len() as u64 - (width.bytes() - 1);
    let addr = addr as u64;
    if addr >= limit {
        return Err(Trap::MemoryOutOfBounds);
    }
    Ok((addr as usize, addr as usize + width.bytes() as usize))
}

struct Frame {
    func: u32,
    block: u32,
    inst: usize,
    base: usize,
    ret_dst: u32,
}

pub(crate) fn run(
    program: &Program,
    entry: u32,
    args: &[i64],
    memory: &mut [u8],
    limits: Limits,
) -> Outcome {
    let mut gas = limits.gas;
    let result = execute(program, entry, args, memory, limits.stack_budget, &mut gas);
    Outcome {
        result,
        gas_used: limits.gas - gas,
    }
}

fn execute(
    program: &Program,
    entry: u32,
    args: &[i64],
    memory: &mut [u8],
    stack_budget: u64,
    gas: &mut u64,
) -> Result<i64, Trap> {
    let mut regs: Vec<i64> = Vec::with_capacity(256);
    let mut frames: Vec<Frame> = Vec::with_capacity(32);
    let mut stack_used = 0u64;

    let func = &program.functions[entry as usize];
    let cost = func.frame_cost();
    if cost > stack_budget {
        return Err(Trap::StackOverflow);
    }
    stack_used += cost;
    regs.resize(func.n_regs as usize, 0);
    regs[..args.len()].copy_from_slice(args);
    frames.push(Frame {
        func: entry,
        block: 0,
        inst: 0,
        base: 0,
        ret_dst: 0,
    });
    charge(func.blocks[0].gas(), gas)?;

    loop {
        let top = frames.len() - 1;
        let (func_id, block_id, inst_index, base) = {
            let f = &frames[top];
            (f.func, f.block, f.inst, f.base)
        };
        let func = &program.functions[func_id as usize];
        let block = &func.blocks[block_id as usize];

        if let Some(inst) = block.insts.get(inst_index) {
            frames[top].inst += 1;
            match inst {
                Inst::Const { dst, value } => regs[base + *dst as usize] = *value,
                Inst::Mov { dst, src } => regs[base + *dst as usize] = regs[base + *src as usize],
                Inst::Bin { op, dst, a, b } => {
                    let v = eval_bin(*op, regs[base + *a as usize], regs[base + *b as usize])?;
                    regs[base + *dst as usize] = v;
                }
                Inst::Un { op, dst, a } => {
                    regs[base + *dst as usize] = eval_un(*op, regs[base + *a as usize]);
                }
                Inst::Load { dst, addr, width } => {
                    let (s, e) = checked_range(memory, regs[base + *addr as usize], *width)?;
                    regs[base + *dst as usize] = match width {
                        Width::W8 => i64::from(memory[s]),
                        Width::W64 => {
                            let mut b = [0u8; 8];
                            b.copy_from_slice(&memory[s..e]);
                            i64::from_le_bytes(b)
                        }
                    };
                }
                Inst::Store { addr, value, width } => {
                    let (s, e) = checked_range(memory, regs[base + *addr as usize], *width)?;
                    let v = regs[base + *value as usize];
                    match width {
                        Width::W8 => memory[s] = v as u8,
                        Width::W64 => memory[s..e].copy_from_slice(&v.to_le_bytes()),
                    }
                }
                Inst::MemSize { dst } => regs[base + *dst as usize] = memory.len() as i64,
                Inst::Call {
                    dst,
                    func: callee,
                    args,
                } => {
                    let target = &program.functions[*callee as usize];
                    let cost = target.frame_cost();
                    if stack_used + cost > stack_budget {
                        return Err(Trap::StackOverflow);
                    }
                    stack_used += cost;
                    let new_base = regs.len();
                    regs.resize(new_base + target.n_regs as usize, 0);
                    for (i, arg) in args.iter().enumerate() {
                        regs[new_base + i] = regs[base + *arg as usize];
                    }
                    frames.push(Frame {
                        func: *callee,
                        block: 0,
                        inst: 0,
                        base: new_base,
                        ret_dst: *dst,
                    });
                    charge(target.blocks[0].gas(), gas)?;
                }
            }
            continue;
        }

        match &block.term {
            Terminator::Jump(next) => enter_block(&mut frames[top], *next, func, gas)?,
            Terminator::Branch {
                cond,
                then_block,
                else_block,
            } => {
                let next = if regs[base + *cond as usize] != 0 {
                    *then_block
                } else {
                    *else_block
                };
                enter_block(&mut frames[top], next, func, gas)?;
            }
            Terminator::Return(r) => {
                let value = regs[base + *r as usize];
                let done = frames.pop().map_or(0, |f| f.ret_dst);
                stack_used -= func.frame_cost();
                regs.truncate(base);
                let Some(caller) = frames.last() else {
                    return Ok(value);
                };
                regs[caller.base + done as usize] = value;
            }
        }
    }
}

fn enter_block(
    frame: &mut Frame,
    next: u32,
    func: &crate::ir::Function,
    gas: &mut u64,
) -> Result<(), Trap> {
    frame.block = next;
    frame.inst = 0;
    charge(func.blocks[next as usize].gas(), gas)
}

#[inline]
fn charge(cost: u64, gas: &mut u64) -> Result<(), Trap> {
    if cost > *gas {
        return Err(Trap::OutOfGas);
    }
    *gas -= cost;
    Ok(())
}
