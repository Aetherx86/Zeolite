//! Register-based intermediate representation and the AST lowering pass.
//!
//! Both execution backends consume this IR, so its block structure defines the metering
//! semantics. A block's whole cost is charged on entry, which makes gas accounting
//! identical between the interpreter and the JIT by construction.

use crate::syntax::{BinOp, CompileError, Expr, FnDecl, Stmt, UnOp, Width};
use std::collections::{BTreeMap, HashMap};

pub type Reg = u32;
pub type BlockId = u32;

/// Upper bound on IR instructions in a program, which bounds compile time.
pub const MAX_PROGRAM_INSTS: usize = 1 << 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inst {
    Const { dst: Reg, value: i64 },
    Mov { dst: Reg, src: Reg },
    Bin { op: BinOp, dst: Reg, a: Reg, b: Reg },
    Un { op: UnOp, dst: Reg, a: Reg },
    Load { dst: Reg, addr: Reg, width: Width },
    Store { addr: Reg, value: Reg, width: Width },
    Call { dst: Reg, func: u32, args: Vec<Reg> },
    MemSize { dst: Reg },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Terminator {
    Jump(BlockId),
    Branch {
        cond: Reg,
        then_block: BlockId,
        else_block: BlockId,
    },
    Return(Reg),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub insts: Vec<Inst>,
    pub term: Terminator,
}

impl Block {
    /// Gas charged on entry: one unit per instruction, including the terminator.
    pub fn gas(&self) -> u64 {
        self.insts.len() as u64 + 1
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Function {
    pub name: String,
    pub n_params: u32,
    pub n_regs: u32,
    pub blocks: Vec<Block>,
}

impl Function {
    /// Deterministic stack charge for one activation.
    ///
    /// This deliberately overestimates the native frame, because register allocation
    /// can never need more than a spill slot per live value plus fixed overhead.
    /// Traps therefore depend only on the program, never on the host's code generator.
    pub fn frame_cost(&self) -> u64 {
        32 * (u64::from(self.n_regs) + 16)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    pub functions: Vec<Function>,
    pub exports: BTreeMap<String, u32>,
}

struct OpenBlock {
    insts: Vec<Inst>,
    term: Option<Terminator>,
}

struct Lower<'a> {
    signatures: &'a HashMap<&'a str, (u32, usize)>,
    blocks: Vec<OpenBlock>,
    current: BlockId,
    n_regs: u32,
    scopes: Vec<HashMap<String, Reg>>,
    loops: Vec<(BlockId, BlockId)>,
    insts: &'a mut usize,
}

pub fn lower(decls: &[FnDecl]) -> Result<Program, CompileError> {
    let mut signatures: HashMap<&str, (u32, usize)> = HashMap::new();
    let mut exports = BTreeMap::new();
    for (i, decl) in decls.iter().enumerate() {
        let previous = signatures.insert(decl.name.as_str(), (i as u32, decl.params.len()));
        if previous.is_some() {
            return Err(CompileError::new(
                decl.line,
                format!("function `{}` is defined twice", decl.name),
            ));
        }
        exports.insert(decl.name.clone(), i as u32);
    }

    let mut total_insts = 0usize;
    let mut functions = Vec::with_capacity(decls.len());
    for decl in decls {
        functions.push(lower_function(decl, &signatures, &mut total_insts)?);
    }
    Ok(Program { functions, exports })
}

fn lower_function(
    decl: &FnDecl,
    signatures: &HashMap<&str, (u32, usize)>,
    total_insts: &mut usize,
) -> Result<Function, CompileError> {
    let mut scope = HashMap::new();
    for (i, param) in decl.params.iter().enumerate() {
        if scope.insert(param.clone(), i as Reg).is_some() {
            return Err(CompileError::new(
                decl.line,
                format!("parameter `{param}` is declared twice"),
            ));
        }
    }
    let mut lower = Lower {
        signatures,
        blocks: vec![OpenBlock {
            insts: Vec::new(),
            term: None,
        }],
        current: 0,
        n_regs: decl.params.len() as u32,
        scopes: vec![scope],
        loops: Vec::new(),
        insts: total_insts,
    };
    lower.stmts(&decl.body)?;

    // Falling off the end of a function returns zero.
    let zero = lower.reg();
    lower.emit(
        Inst::Const {
            dst: zero,
            value: 0,
        },
        decl.line,
    )?;
    lower.terminate(Terminator::Return(zero));

    let blocks = lower
        .blocks
        .into_iter()
        .map(|b| Block {
            insts: b.insts,
            // Every block left open here is unreachable and only needs a valid shape.
            term: b.term.unwrap_or(Terminator::Return(zero)),
        })
        .collect();
    Ok(Function {
        name: decl.name.clone(),
        n_params: decl.params.len() as u32,
        n_regs: lower.n_regs,
        blocks,
    })
}

impl Lower<'_> {
    fn reg(&mut self) -> Reg {
        let r = self.n_regs;
        self.n_regs += 1;
        r
    }

    fn new_block(&mut self) -> BlockId {
        self.blocks.push(OpenBlock {
            insts: Vec::new(),
            term: None,
        });
        (self.blocks.len() - 1) as BlockId
    }

    fn emit(&mut self, inst: Inst, line: u32) -> Result<(), CompileError> {
        *self.insts += 1;
        if *self.insts > MAX_PROGRAM_INSTS {
            return Err(CompileError::new(
                line,
                format!("program exceeds {MAX_PROGRAM_INSTS} instructions"),
            ));
        }
        self.blocks[self.current as usize].insts.push(inst);
        Ok(())
    }

    fn terminate(&mut self, term: Terminator) {
        let block = &mut self.blocks[self.current as usize];
        if block.term.is_none() {
            block.term = Some(term);
        }
    }

    fn resolve(&self, name: &str) -> Option<Reg> {
        self.scopes.iter().rev().find_map(|s| s.get(name).copied())
    }

    fn stmts(&mut self, stmts: &[Stmt]) -> Result<(), CompileError> {
        self.scopes.push(HashMap::new());
        for stmt in stmts {
            self.stmt(stmt)?;
        }
        self.scopes.pop();
        Ok(())
    }

    fn stmt(&mut self, stmt: &Stmt) -> Result<(), CompileError> {
        match stmt {
            Stmt::Let(name, value, _) => {
                let result = self.expr(value)?;
                // A fresh register keeps shadowing and loop-local bindings simple.
                let slot = self.reg();
                self.emit(
                    Inst::Mov {
                        dst: slot,
                        src: result,
                    },
                    0,
                )?;
                if let Some(scope) = self.scopes.last_mut() {
                    scope.insert(name.clone(), slot);
                }
            }
            Stmt::Assign(name, value, line) => {
                let slot = self.resolve(name).ok_or_else(|| {
                    CompileError::new(*line, format!("assignment to undeclared variable `{name}`"))
                })?;
                let result = self.expr(value)?;
                self.emit(
                    Inst::Mov {
                        dst: slot,
                        src: result,
                    },
                    *line,
                )?;
            }
            Stmt::If(cond, then_body, else_body) => {
                let c = self.expr(cond)?;
                let then_block = self.new_block();
                let else_block = self.new_block();
                let join = self.new_block();
                self.terminate(Terminator::Branch {
                    cond: c,
                    then_block,
                    else_block,
                });
                self.current = then_block;
                self.stmts(then_body)?;
                self.terminate(Terminator::Jump(join));
                self.current = else_block;
                self.stmts(else_body)?;
                self.terminate(Terminator::Jump(join));
                self.current = join;
            }
            Stmt::While(cond, body) => {
                let head = self.new_block();
                let body_block = self.new_block();
                let exit = self.new_block();
                self.terminate(Terminator::Jump(head));
                self.current = head;
                let c = self.expr(cond)?;
                self.terminate(Terminator::Branch {
                    cond: c,
                    then_block: body_block,
                    else_block: exit,
                });
                self.current = body_block;
                self.loops.push((head, exit));
                self.stmts(body)?;
                self.loops.pop();
                self.terminate(Terminator::Jump(head));
                self.current = exit;
            }
            Stmt::Return(value) => {
                let r = match value {
                    Some(v) => self.expr(v)?,
                    None => {
                        let r = self.reg();
                        self.emit(Inst::Const { dst: r, value: 0 }, 0)?;
                        r
                    }
                };
                self.terminate(Terminator::Return(r));
                // Anything after this statement is unreachable but still has to lower.
                self.current = self.new_block();
            }
            Stmt::Break(line) => {
                let (_, exit) = *self
                    .loops
                    .last()
                    .ok_or_else(|| CompileError::new(*line, "`break` outside of a loop"))?;
                self.terminate(Terminator::Jump(exit));
                self.current = self.new_block();
            }
            Stmt::Continue(line) => {
                let (head, _) = *self
                    .loops
                    .last()
                    .ok_or_else(|| CompileError::new(*line, "`continue` outside of a loop"))?;
                self.terminate(Terminator::Jump(head));
                self.current = self.new_block();
            }
            Stmt::Store(addr, value, width) => {
                let a = self.expr(addr)?;
                let v = self.expr(value)?;
                self.emit(
                    Inst::Store {
                        addr: a,
                        value: v,
                        width: *width,
                    },
                    0,
                )?;
            }
            Stmt::Expr(expr) => {
                self.expr(expr)?;
            }
        }
        Ok(())
    }

    fn expr(&mut self, expr: &Expr) -> Result<Reg, CompileError> {
        match expr {
            Expr::Int(value) => {
                let dst = self.reg();
                self.emit(Inst::Const { dst, value: *value }, 0)?;
                Ok(dst)
            }
            Expr::Var(name) => self.resolve(name).ok_or_else(|| {
                CompileError::new(0, format!("use of undeclared variable `{name}`"))
            }),
            Expr::Bin(op, a, b) => {
                let a = self.operand(a)?;
                let b = self.expr(b)?;
                let dst = self.reg();
                self.emit(Inst::Bin { op: *op, dst, a, b }, 0)?;
                Ok(dst)
            }
            Expr::Un(op, a) => {
                let a = self.expr(a)?;
                let dst = self.reg();
                self.emit(Inst::Un { op: *op, dst, a }, 0)?;
                Ok(dst)
            }
            Expr::LogicalAnd(a, b) => self.short_circuit(a, b, true),
            Expr::LogicalOr(a, b) => self.short_circuit(a, b, false),
            Expr::Call(name, args, line) => {
                let (func, arity) = *self.signatures.get(name.as_str()).ok_or_else(|| {
                    CompileError::new(*line, format!("call to undefined function `{name}`"))
                })?;
                if arity != args.len() {
                    return Err(CompileError::new(
                        *line,
                        format!(
                            "function `{name}` takes {arity} arguments but {} were supplied",
                            args.len()
                        ),
                    ));
                }
                let mut regs = Vec::with_capacity(args.len());
                for arg in args {
                    regs.push(self.operand(arg)?);
                }
                let dst = self.reg();
                self.emit(
                    Inst::Call {
                        dst,
                        func,
                        args: regs,
                    },
                    *line,
                )?;
                Ok(dst)
            }
            Expr::Load(addr, width) => {
                let addr = self.expr(addr)?;
                let dst = self.reg();
                self.emit(
                    Inst::Load {
                        dst,
                        addr,
                        width: *width,
                    },
                    0,
                )?;
                Ok(dst)
            }
            Expr::MemSize => {
                let dst = self.reg();
                self.emit(Inst::MemSize { dst }, 0)?;
                Ok(dst)
            }
        }
    }

    /// Evaluates an operand that must hold its value while later operands evaluate.
    ///
    /// A variable read returns the variable's own register. In `x + f(x = 1)`-style
    /// shapes that register could change before use, so it is copied when the operand
    /// is a variable. Zel has no assignment expressions today, but calls and short
    /// circuits still make the copy the conservative, always-correct choice.
    fn operand(&mut self, expr: &Expr) -> Result<Reg, CompileError> {
        let r = self.expr(expr)?;
        if matches!(expr, Expr::Var(_)) {
            let dst = self.reg();
            self.emit(Inst::Mov { dst, src: r }, 0)?;
            return Ok(dst);
        }
        Ok(r)
    }

    fn short_circuit(&mut self, a: &Expr, b: &Expr, is_and: bool) -> Result<Reg, CompileError> {
        let result = self.reg();
        let left = self.expr(a)?;
        let right_block = self.new_block();
        let short_block = self.new_block();
        let join = self.new_block();
        let (then_block, else_block) = if is_and {
            (right_block, short_block)
        } else {
            (short_block, right_block)
        };
        self.terminate(Terminator::Branch {
            cond: left,
            then_block,
            else_block,
        });

        self.current = short_block;
        self.emit(
            Inst::Const {
                dst: result,
                value: i64::from(!is_and),
            },
            0,
        )?;
        self.terminate(Terminator::Jump(join));

        self.current = right_block;
        let right = self.expr(b)?;
        let zero = self.reg();
        self.emit(
            Inst::Const {
                dst: zero,
                value: 0,
            },
            0,
        )?;
        // Both operators yield exactly 0 or 1, whatever the operand values were.
        self.emit(
            Inst::Bin {
                op: BinOp::Ne,
                dst: result,
                a: right,
                b: zero,
            },
            0,
        )?;
        self.terminate(Terminator::Jump(join));

        self.current = join;
        Ok(result)
    }
}
