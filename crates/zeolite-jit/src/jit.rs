//! Native code generation through Cranelift.
//!
//! Generated code never relies on signals. Every condition that could fault is checked
//! explicitly and reported by writing a code to `VmCtx::trap` and returning, so a guest
//! fault cannot take down the host process:
//!
//! - gas is checked on block entry,
//! - memory accesses are bounds-checked,
//! - division is guarded against zero and overflow,
//! - recursion is bounded by a deterministic per-frame stack charge.

use crate::ir::{Inst, Program, Terminator};
use crate::syntax::{BinOp, CompileError, UnOp, Width};
use crate::{Limits, Outcome, Trap};
use cranelift_codegen::ir::condcodes::IntCC;
use cranelift_codegen::ir::{self, AbiParam, InstBuilder, MemFlagsData, UserFuncName, types};
use cranelift_codegen::settings::{self, Configurable};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext, Variable};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{FuncId, Linkage, Module, default_libcall_names};
use std::collections::HashMap;

#[repr(C)]
pub(crate) struct VmCtx {
    gas: u64,
    mem_base: *mut u8,
    mem_len: u64,
    stack_used: u64,
    stack_budget: u64,
    trap: u64,
}

const OFF_GAS: i32 = 0;
const OFF_MEM_BASE: i32 = 8;
const OFF_MEM_LEN: i32 = 16;
const OFF_STACK_USED: i32 = 24;
const OFF_STACK_BUDGET: i32 = 32;
const OFF_TRAP: i32 = 40;

const TRAP_OUT_OF_GAS: i64 = 1;
const TRAP_MEMORY: i64 = 2;
const TRAP_DIV_ZERO: i64 = 3;
const TRAP_OVERFLOW: i64 = 4;
const TRAP_STACK: i64 = 5;

fn trap_from_code(code: u64) -> Trap {
    match code as i64 {
        TRAP_OUT_OF_GAS => Trap::OutOfGas,
        TRAP_MEMORY => Trap::MemoryOutOfBounds,
        TRAP_DIV_ZERO => Trap::DivideByZero,
        TRAP_OVERFLOW => Trap::IntegerOverflow,
        _ => Trap::StackOverflow,
    }
}

pub(crate) struct JitCode {
    module: Option<JITModule>,
    entries: Vec<*const u8>,
}

// SAFETY: after `finalize_definitions` the code pages are immutable, and the module is
// only touched again by `Drop`, which has exclusive access. The stored pointers refer to
// that immutable code, so sharing them across threads is sound.
unsafe impl Send for JitCode {}
// SAFETY: see the `Send` impl above.
unsafe impl Sync for JitCode {}

impl Drop for JitCode {
    fn drop(&mut self) {
        if let Some(module) = self.module.take() {
            // SAFETY: `JitCode` owns the only pointers into this code. They die with it,
            // and `run` borrows `self`, so no guest code can be executing here.
            unsafe { module.free_memory() };
        }
    }
}

impl JitCode {
    pub(crate) fn compile(program: &Program) -> Result<JitCode, CompileError> {
        let internal = |e: String| CompileError::new(0, format!("code generation failed: {e}"));

        let mut flags = settings::builder();
        flags
            .set("opt_level", "speed")
            .map_err(|e| internal(e.to_string()))?;
        flags
            .set("is_pic", "false")
            .map_err(|e| internal(e.to_string()))?;
        flags
            .set("use_colocated_libcalls", "false")
            .map_err(|e| internal(e.to_string()))?;
        let isa = cranelift_native::builder()
            .map_err(|e| internal(e.to_string()))?
            .finish(settings::Flags::new(flags))
            .map_err(|e| internal(e.to_string()))?;

        let mut module = JITModule::new(JITBuilder::with_isa(isa, default_libcall_names()));
        let call_conv = module.isa().default_call_conv();

        let mut ids: Vec<FuncId> = Vec::with_capacity(program.functions.len());
        for (i, func) in program.functions.iter().enumerate() {
            let mut sig = module.make_signature();
            sig.call_conv = call_conv;
            sig.params.push(AbiParam::new(types::I64));
            for _ in 0..func.n_params {
                sig.params.push(AbiParam::new(types::I64));
            }
            sig.returns.push(AbiParam::new(types::I64));
            // Names are generated so that a guest cannot collide with a host symbol.
            let id = module
                .declare_function(&format!("zel_{i}"), Linkage::Local, &sig)
                .map_err(|e| internal(e.to_string()))?;
            ids.push(id);
        }

        let mut ctx = module.make_context();
        let mut builder_ctx = FunctionBuilderContext::new();
        for (i, id) in ids.iter().enumerate() {
            let decl = module.declarations().get_function_decl(*id);
            ctx.func.signature = decl.signature.clone();
            ctx.func.name = UserFuncName::user(0, i as u32);
            translate(
                program,
                i,
                &ids,
                &mut module,
                &mut ctx.func,
                &mut builder_ctx,
            );
            module
                .define_function(*id, &mut ctx)
                .map_err(|e| internal(format!("{e:?}")))?;
            module.clear_context(&mut ctx);
        }
        module
            .finalize_definitions()
            .map_err(|e| internal(e.to_string()))?;

        let entries = ids
            .iter()
            .map(|id| module.get_finalized_function(*id))
            .collect();
        Ok(JitCode {
            module: Some(module),
            entries,
        })
    }

    pub(crate) fn run(
        &self,
        entry: u32,
        args: &[i64],
        memory: &mut [u8],
        limits: Limits,
    ) -> Outcome {
        let mut vm = VmCtx {
            gas: limits.gas,
            mem_base: memory.as_mut_ptr(),
            mem_len: memory.len() as u64,
            stack_used: 0,
            stack_budget: limits.stack_budget,
            trap: 0,
        };
        let code = self.entries[entry as usize];
        // SAFETY: `code` was generated for exactly `args.len()` parameters, checked by the
        // caller, using the platform C calling convention. `vm` and `memory` outlive the
        // call, and generated code only touches memory through bounds-checked accesses.
        let value = unsafe { invoke(code, &mut vm, args) };
        let result = if vm.trap == 0 {
            Ok(value)
        } else {
            Err(trap_from_code(vm.trap))
        };
        Outcome {
            result,
            gas_used: limits.gas - vm.gas,
        }
    }
}

unsafe fn invoke(code: *const u8, vm: *mut VmCtx, a: &[i64]) -> i64 {
    use std::mem::transmute as t;
    type V = *mut VmCtx;
    // SAFETY: the caller guarantees that `code` has the signature selected by `a.len()`.
    unsafe {
        match a.len() {
            0 => t::<*const u8, extern "C" fn(V) -> i64>(code)(vm),
            1 => t::<*const u8, extern "C" fn(V, i64) -> i64>(code)(vm, a[0]),
            2 => t::<*const u8, extern "C" fn(V, i64, i64) -> i64>(code)(vm, a[0], a[1]),
            3 => t::<*const u8, extern "C" fn(V, i64, i64, i64) -> i64>(code)(vm, a[0], a[1], a[2]),
            4 => t::<*const u8, extern "C" fn(V, i64, i64, i64, i64) -> i64>(code)(
                vm, a[0], a[1], a[2], a[3],
            ),
            5 => t::<*const u8, extern "C" fn(V, i64, i64, i64, i64, i64) -> i64>(code)(
                vm, a[0], a[1], a[2], a[3], a[4],
            ),
            6 => t::<*const u8, extern "C" fn(V, i64, i64, i64, i64, i64, i64) -> i64>(code)(
                vm, a[0], a[1], a[2], a[3], a[4], a[5],
            ),
            7 => t::<*const u8, extern "C" fn(V, i64, i64, i64, i64, i64, i64, i64) -> i64>(code)(
                vm, a[0], a[1], a[2], a[3], a[4], a[5], a[6],
            ),
            _ => t::<*const u8, extern "C" fn(V, i64, i64, i64, i64, i64, i64, i64, i64) -> i64>(
                code,
            )(vm, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]),
        }
    }
}

struct Translator<'a, 'b> {
    b: FunctionBuilder<'a>,
    vm: ir::Value,
    vars: Vec<Variable>,
    trap_blocks: HashMap<i64, ir::Block>,
    frame_cost: i64,
    module: &'b mut JITModule,
    ids: &'b [FuncId],
    func_refs: HashMap<u32, ir::FuncRef>,
}

fn trusted() -> MemFlagsData {
    MemFlagsData::trusted()
}

fn guest_flags() -> MemFlagsData {
    // Guest accesses may be unaligned and are little-endian on every host. They were
    // already bounds-checked, so they cannot fault.
    MemFlagsData::new()
        .with_endianness(ir::Endianness::Little)
        .with_notrap()
}

impl Translator<'_, '_> {
    fn trap_block(&mut self, code: i64) -> ir::Block {
        if let Some(block) = self.trap_blocks.get(&code) {
            return *block;
        }
        let block = self.b.create_block();
        self.b.set_cold_block(block);
        self.trap_blocks.insert(code, block);
        block
    }

    /// Branches to the trap block for `code` when `failed` is non-zero.
    fn trap_if(&mut self, failed: ir::Value, code: i64) {
        let trap = self.trap_block(code);
        let cont = self.b.create_block();
        self.b.ins().brif(failed, trap, &[], cont, &[]);
        self.b.switch_to_block(cont);
    }

    fn charge_gas(&mut self, cost: u64) {
        let gas = self.b.ins().load(types::I64, trusted(), self.vm, OFF_GAS);
        let cost = self.b.ins().iconst(types::I64, cost as i64);
        let short = self.b.ins().icmp(IntCC::UnsignedLessThan, gas, cost);
        self.trap_if(short, TRAP_OUT_OF_GAS);
        let remaining = self.b.ins().isub(gas, cost);
        self.b.ins().store(trusted(), remaining, self.vm, OFF_GAS);
    }

    fn guest_address(&mut self, addr: ir::Value, width: Width) -> ir::Value {
        let len = self
            .b
            .ins()
            .load(types::I64, trusted(), self.vm, OFF_MEM_LEN);
        // `len >= 8` is guaranteed on entry, so this subtraction cannot wrap.
        let limit = self.b.ins().iadd_imm_s(len, -((width.bytes() - 1) as i64));
        let out = self
            .b
            .ins()
            .icmp(IntCC::UnsignedGreaterThanOrEqual, addr, limit);
        self.trap_if(out, TRAP_MEMORY);
        let base = self
            .b
            .ins()
            .load(types::I64, trusted(), self.vm, OFF_MEM_BASE);
        self.b.ins().iadd(base, addr)
    }

    fn bool_to_i64(&mut self, cond: ir::Value) -> ir::Value {
        self.b.ins().uextend(types::I64, cond)
    }

    fn bin(&mut self, op: BinOp, a: ir::Value, b: ir::Value) -> ir::Value {
        match op {
            BinOp::Add => self.b.ins().iadd(a, b),
            BinOp::Sub => self.b.ins().isub(a, b),
            BinOp::Mul => self.b.ins().imul(a, b),
            BinOp::Div => {
                let zero = self.b.ins().icmp_imm_s(IntCC::Equal, b, 0);
                self.trap_if(zero, TRAP_DIV_ZERO);
                let min = self.b.ins().iconst(types::I64, i64::MIN);
                let a_min = self.b.ins().icmp(IntCC::Equal, a, min);
                let b_neg1 = self.b.ins().icmp_imm_s(IntCC::Equal, b, -1);
                let overflow = self.b.ins().band(a_min, b_neg1);
                self.trap_if(overflow, TRAP_OVERFLOW);
                self.b.ins().sdiv(a, b)
            }
            BinOp::Rem => {
                let zero = self.b.ins().icmp_imm_s(IntCC::Equal, b, 0);
                self.trap_if(zero, TRAP_DIV_ZERO);
                let neg1 = self.b.ins().icmp_imm_s(IntCC::Equal, b, -1);
                let do_rem = self.b.create_block();
                let join = self.b.create_block();
                let result = self.b.append_block_param(join, types::I64);
                let zero_value = self.b.ins().iconst(types::I64, 0);
                self.b
                    .ins()
                    .brif(neg1, join, &[ir::BlockArg::Value(zero_value)], do_rem, &[]);
                self.b.switch_to_block(do_rem);
                let rem = self.b.ins().srem(a, b);
                self.b.ins().jump(join, &[ir::BlockArg::Value(rem)]);
                self.b.switch_to_block(join);
                result
            }
            BinOp::And => self.b.ins().band(a, b),
            BinOp::Or => self.b.ins().bor(a, b),
            BinOp::Xor => self.b.ins().bxor(a, b),
            // Cranelift masks the shift amount to the type width, matching the interpreter.
            BinOp::Shl => self.b.ins().ishl(a, b),
            BinOp::Shr => self.b.ins().sshr(a, b),
            BinOp::ShrU => self.b.ins().ushr(a, b),
            BinOp::Eq => self.cmp(IntCC::Equal, a, b),
            BinOp::Ne => self.cmp(IntCC::NotEqual, a, b),
            BinOp::Lt => self.cmp(IntCC::SignedLessThan, a, b),
            BinOp::Le => self.cmp(IntCC::SignedLessThanOrEqual, a, b),
            BinOp::Gt => self.cmp(IntCC::SignedGreaterThan, a, b),
            BinOp::Ge => self.cmp(IntCC::SignedGreaterThanOrEqual, a, b),
        }
    }

    fn cmp(&mut self, cc: IntCC, a: ir::Value, b: ir::Value) -> ir::Value {
        let c = self.b.ins().icmp(cc, a, b);
        self.bool_to_i64(c)
    }

    fn return_value(&mut self, value: ir::Value) {
        let used = self
            .b
            .ins()
            .load(types::I64, trusted(), self.vm, OFF_STACK_USED);
        let restored = self.b.ins().iadd_imm_s(used, -self.frame_cost);
        self.b
            .ins()
            .store(trusted(), restored, self.vm, OFF_STACK_USED);
        self.b.ins().return_(&[value]);
    }

    fn call(&mut self, func: u32, args: &[ir::Value]) -> ir::Value {
        let func_ref = match self.func_refs.get(&func) {
            Some(r) => *r,
            None => {
                let r = self
                    .module
                    .declare_func_in_func(self.ids[func as usize], self.b.func);
                self.func_refs.insert(func, r);
                r
            }
        };
        let mut full = Vec::with_capacity(args.len() + 1);
        full.push(self.vm);
        full.extend_from_slice(args);
        let inst = self.b.ins().call(func_ref, &full);
        let value = self.b.inst_results(inst)[0];

        // A callee that trapped unwinds by returning. Propagate it upward immediately.
        let trap = self.b.ins().load(types::I64, trusted(), self.vm, OFF_TRAP);
        let unwind = self.b.create_block();
        self.b.set_cold_block(unwind);
        let cont = self.b.create_block();
        self.b.ins().brif(trap, unwind, &[], cont, &[]);
        self.b.switch_to_block(unwind);
        let zero = self.b.ins().iconst(types::I64, 0);
        self.b.ins().return_(&[zero]);
        self.b.switch_to_block(cont);
        value
    }
}

fn translate(
    program: &Program,
    index: usize,
    ids: &[FuncId],
    module: &mut JITModule,
    func: &mut ir::Function,
    builder_ctx: &mut FunctionBuilderContext,
) {
    let source = &program.functions[index];
    let mut b = FunctionBuilder::new(func, builder_ctx);

    let entry = b.create_block();
    b.append_block_params_for_function_params(entry);
    b.switch_to_block(entry);

    let params: Vec<ir::Value> = b.block_params(entry).to_vec();
    let vm = params[0];
    let vars: Vec<Variable> = (0..source.n_regs)
        .map(|_| b.declare_var(types::I64))
        .collect();

    // Registers start at zero to match the interpreter.
    for (i, var) in vars.iter().enumerate() {
        let init = if i < source.n_params as usize {
            params[i + 1]
        } else {
            b.ins().iconst(types::I64, 0)
        };
        b.def_var(*var, init);
    }

    let frame_cost = source.frame_cost() as i64;
    let mut t = Translator {
        b,
        vm,
        vars,
        trap_blocks: HashMap::new(),
        frame_cost,
        module,
        ids,
        func_refs: HashMap::new(),
    };

    // Deterministic stack check, in the same order as the interpreter: before gas.
    let used = t.b.ins().load(types::I64, trusted(), vm, OFF_STACK_USED);
    let next_used = t.b.ins().iadd_imm_s(used, frame_cost);
    let budget = t.b.ins().load(types::I64, trusted(), vm, OFF_STACK_BUDGET);
    let over =
        t.b.ins()
            .icmp(IntCC::UnsignedGreaterThan, next_used, budget);
    t.trap_if(over, TRAP_STACK);
    t.b.ins().store(trusted(), next_used, vm, OFF_STACK_USED);

    let blocks: Vec<ir::Block> = source.blocks.iter().map(|_| t.b.create_block()).collect();
    t.b.ins().jump(blocks[0], &[]);

    for (i, block) in source.blocks.iter().enumerate() {
        t.b.switch_to_block(blocks[i]);
        t.charge_gas(block.gas());
        for inst in &block.insts {
            match inst {
                Inst::Const { dst, value } => {
                    let v = t.b.ins().iconst(types::I64, *value);
                    t.b.def_var(t.vars[*dst as usize], v);
                }
                Inst::Mov { dst, src } => {
                    let v = t.b.use_var(t.vars[*src as usize]);
                    t.b.def_var(t.vars[*dst as usize], v);
                }
                Inst::Bin { op, dst, a, b } => {
                    let a = t.b.use_var(t.vars[*a as usize]);
                    let b = t.b.use_var(t.vars[*b as usize]);
                    let v = t.bin(*op, a, b);
                    t.b.def_var(t.vars[*dst as usize], v);
                }
                Inst::Un { op, dst, a } => {
                    let a = t.b.use_var(t.vars[*a as usize]);
                    let v = match op {
                        UnOp::Neg => t.b.ins().ineg(a),
                        UnOp::BitNot => t.b.ins().bnot(a),
                        UnOp::Not => {
                            let c = t.b.ins().icmp_imm_s(IntCC::Equal, a, 0);
                            t.bool_to_i64(c)
                        }
                    };
                    t.b.def_var(t.vars[*dst as usize], v);
                }
                Inst::Load { dst, addr, width } => {
                    let a = t.b.use_var(t.vars[*addr as usize]);
                    let p = t.guest_address(a, *width);
                    let v = match width {
                        Width::W8 => t.b.ins().uload8(types::I64, guest_flags(), p, 0),
                        Width::W64 => t.b.ins().load(types::I64, guest_flags(), p, 0),
                    };
                    t.b.def_var(t.vars[*dst as usize], v);
                }
                Inst::Store { addr, value, width } => {
                    let a = t.b.use_var(t.vars[*addr as usize]);
                    let v = t.b.use_var(t.vars[*value as usize]);
                    let p = t.guest_address(a, *width);
                    match width {
                        Width::W8 => {
                            t.b.ins().istore8(guest_flags(), v, p, 0);
                        }
                        Width::W64 => {
                            t.b.ins().store(guest_flags(), v, p, 0);
                        }
                    }
                }
                Inst::MemSize { dst } => {
                    let v = t.b.ins().load(types::I64, trusted(), t.vm, OFF_MEM_LEN);
                    t.b.def_var(t.vars[*dst as usize], v);
                }
                Inst::Call { dst, func, args } => {
                    let values: Vec<ir::Value> = args
                        .iter()
                        .map(|r| t.b.use_var(t.vars[*r as usize]))
                        .collect();
                    let v = t.call(*func, &values);
                    t.b.def_var(t.vars[*dst as usize], v);
                }
            }
        }
        match &block.term {
            Terminator::Jump(next) => {
                t.b.ins().jump(blocks[*next as usize], &[]);
            }
            Terminator::Branch {
                cond,
                then_block,
                else_block,
            } => {
                let c = t.b.use_var(t.vars[*cond as usize]);
                t.b.ins().brif(
                    c,
                    blocks[*then_block as usize],
                    &[],
                    blocks[*else_block as usize],
                    &[],
                );
            }
            Terminator::Return(r) => {
                let v = t.b.use_var(t.vars[*r as usize]);
                t.return_value(v);
            }
        }
    }

    let traps: Vec<(i64, ir::Block)> = t.trap_blocks.iter().map(|(c, b)| (*c, *b)).collect();
    for (code, block) in traps {
        t.b.switch_to_block(block);
        let code = t.b.ins().iconst(types::I64, code);
        t.b.ins().store(trusted(), code, vm, OFF_TRAP);
        let zero = t.b.ins().iconst(types::I64, 0);
        t.b.ins().return_(&[zero]);
    }

    t.b.seal_all_blocks();
    let target_config = t.module.target_config();
    t.b.finalize(target_config);
}
