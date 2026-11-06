//! Lexer and recursive-descent parser for Zel, a small statement language over `i64`.
//!
//! ```text
//! fn add_to_slot(slot, amount) {
//!     let value = load(slot * 8) + amount;
//!     store(slot * 8, value);
//!     return value;
//! }
//! ```
//!
//! Source text is untrusted. Size, nesting depth and item counts are all bounded so that
//! a hostile program cannot exhaust the parser's stack or the compiler's time.

use std::fmt;

pub const MAX_SOURCE_BYTES: usize = 1 << 20;
pub const MAX_NESTING: usize = 64;
/// Later passes walk expressions recursively, so tree height is bounded as well. Nesting
/// alone cannot catch `1 + 1 + 1 + ...`, which parses in a loop into a deep left spine.
pub const MAX_EXPR_HEIGHT: u32 = 256;
pub const MAX_PARAMS: usize = 8;
pub const MAX_FUNCTIONS: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompileError {
    pub line: u32,
    pub message: String,
}

impl CompileError {
    pub fn new(line: u32, message: impl Into<String>) -> Self {
        CompileError {
            line,
            message: message.into(),
        }
    }
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for CompileError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    ShrU,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UnOp {
    Neg,
    Not,
    BitNot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Width {
    W8,
    W64,
}

impl Width {
    pub fn bytes(self) -> u64 {
        match self {
            Width::W8 => 1,
            Width::W64 => 8,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    Int(i64),
    Var(String),
    Bin(BinOp, Box<Expr>, Box<Expr>),
    Un(UnOp, Box<Expr>),
    LogicalAnd(Box<Expr>, Box<Expr>),
    LogicalOr(Box<Expr>, Box<Expr>),
    Call(String, Vec<Expr>, u32),
    Load(Box<Expr>, Width),
    MemSize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stmt {
    Let(String, Expr, u32),
    Assign(String, Expr, u32),
    If(Expr, Vec<Stmt>, Vec<Stmt>),
    While(Expr, Vec<Stmt>),
    Return(Option<Expr>),
    Break(u32),
    Continue(u32),
    Store(Expr, Expr, Width),
    Expr(Expr),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FnDecl {
    pub name: String,
    pub params: Vec<String>,
    pub body: Vec<Stmt>,
    pub line: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Tok {
    Int(i64),
    Ident(String),
    Punct(&'static str),
    Eof,
}

struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
    line: u32,
}

const PUNCTS: &[&str] = &[
    ">>>", "==", "!=", "<=", ">=", "<<", ">>", "&&", "||", "(", ")", "{", "}", ",", ";", "=", "+",
    "-", "*", "/", "%", "&", "|", "^", "~", "!", "<", ">",
];

impl Lexer<'_> {
    fn skip_trivia(&mut self) {
        while self.pos < self.src.len() {
            let c = self.src[self.pos];
            if c == b'\n' {
                self.line += 1;
                self.pos += 1;
            } else if c.is_ascii_whitespace() {
                self.pos += 1;
            } else if c == b'/' && self.src.get(self.pos + 1) == Some(&b'/') {
                while self.pos < self.src.len() && self.src[self.pos] != b'\n' {
                    self.pos += 1;
                }
            } else {
                break;
            }
        }
    }

    fn next(&mut self) -> Result<(Tok, u32), CompileError> {
        self.skip_trivia();
        let line = self.line;
        let Some(&c) = self.src.get(self.pos) else {
            return Ok((Tok::Eof, line));
        };
        if c.is_ascii_digit() {
            return self.number().map(|t| (t, line));
        }
        if c.is_ascii_alphabetic() || c == b'_' {
            let start = self.pos;
            while self
                .src
                .get(self.pos)
                .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
            {
                self.pos += 1;
            }
            // Identifier bytes are all ASCII, so this conversion cannot fail.
            let ident = std::str::from_utf8(&self.src[start..self.pos])
                .map_err(|_| CompileError::new(line, "invalid identifier"))?;
            return Ok((Tok::Ident(ident.to_string()), line));
        }
        for p in PUNCTS {
            if self.src[self.pos..].starts_with(p.as_bytes()) {
                self.pos += p.len();
                return Ok((Tok::Punct(p), line));
            }
        }
        Err(CompileError::new(
            line,
            format!("unexpected character {:?}", c as char),
        ))
    }

    fn number(&mut self) -> Result<Tok, CompileError> {
        let start = self.pos;
        let hex =
            self.src[self.pos..].starts_with(b"0x") || self.src[self.pos..].starts_with(b"0X");
        if hex {
            self.pos += 2;
        }
        let digits_start = self.pos;
        while self
            .src
            .get(self.pos)
            .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
        {
            self.pos += 1;
        }
        let text: String = self.src[digits_start..self.pos]
            .iter()
            .filter(|c| **c != b'_')
            .map(|c| *c as char)
            .collect();
        let bad = || {
            CompileError::new(
                self.line,
                format!(
                    "invalid integer literal {:?}",
                    String::from_utf8_lossy(&self.src[start..self.pos])
                ),
            )
        };
        let value = if hex {
            // Hex literals name a bit pattern, so 0xFFFFFFFFFFFFFFFF is -1.
            u64::from_str_radix(&text, 16).map_err(|_| bad())? as i64
        } else {
            // i64::MIN has no positive literal, so allow its magnitude as a wrapped value.
            text.parse::<u64>().map_err(|_| bad())? as i64
        };
        Ok(Tok::Int(value))
    }
}

struct Parser<'a> {
    lex: Lexer<'a>,
    tok: Tok,
    line: u32,
    depth: usize,
}

pub fn parse(src: &str) -> Result<Vec<FnDecl>, CompileError> {
    if src.len() > MAX_SOURCE_BYTES {
        return Err(CompileError::new(
            1,
            format!("source exceeds the {MAX_SOURCE_BYTES} byte limit"),
        ));
    }
    let mut lex = Lexer {
        src: src.as_bytes(),
        pos: 0,
        line: 1,
    };
    let (tok, line) = lex.next()?;
    let mut parser = Parser {
        lex,
        tok,
        line,
        depth: 0,
    };
    let mut functions = Vec::new();
    while parser.tok != Tok::Eof {
        if functions.len() >= MAX_FUNCTIONS {
            return Err(parser.err(format!("more than {MAX_FUNCTIONS} functions")));
        }
        functions.push(parser.function()?);
    }
    Ok(functions)
}

impl Parser<'_> {
    fn err(&self, message: impl Into<String>) -> CompileError {
        CompileError::new(self.line, message)
    }

    fn advance(&mut self) -> Result<(), CompileError> {
        let (tok, line) = self.lex.next()?;
        self.tok = tok;
        self.line = line;
        Ok(())
    }

    fn at(&self, p: &str) -> bool {
        matches!(&self.tok, Tok::Punct(q) if *q == p)
    }

    fn at_kw(&self, kw: &str) -> bool {
        matches!(&self.tok, Tok::Ident(s) if s == kw)
    }

    fn eat(&mut self, p: &str) -> Result<bool, CompileError> {
        if self.at(p) {
            self.advance()?;
            return Ok(true);
        }
        Ok(false)
    }

    fn expect(&mut self, p: &str) -> Result<(), CompileError> {
        if self.eat(p)? {
            return Ok(());
        }
        Err(self.err(format!("expected `{p}`, found {:?}", self.tok)))
    }

    fn expect_kw(&mut self, kw: &str) -> Result<(), CompileError> {
        if self.at_kw(kw) {
            return self.advance();
        }
        Err(self.err(format!("expected `{kw}`, found {:?}", self.tok)))
    }

    fn ident(&mut self) -> Result<String, CompileError> {
        match &self.tok {
            Tok::Ident(s) => {
                if is_keyword(s) {
                    return Err(self.err(format!("`{s}` is a reserved word")));
                }
                let s = s.clone();
                self.advance()?;
                Ok(s)
            }
            other => Err(self.err(format!("expected an identifier, found {other:?}"))),
        }
    }

    fn enter(&mut self) -> Result<(), CompileError> {
        self.depth += 1;
        if self.depth > MAX_NESTING {
            return Err(self.err(format!("nesting exceeds {MAX_NESTING} levels")));
        }
        Ok(())
    }

    fn function(&mut self) -> Result<FnDecl, CompileError> {
        let line = self.line;
        self.expect_kw("fn")?;
        let name = self.ident()?;
        self.expect("(")?;
        let mut params = Vec::new();
        while !self.at(")") {
            params.push(self.ident()?);
            if !self.eat(",")? {
                break;
            }
        }
        self.expect(")")?;
        if params.len() > MAX_PARAMS {
            return Err(CompileError::new(
                line,
                format!("function `{name}` has more than {MAX_PARAMS} parameters"),
            ));
        }
        let body = self.block()?;
        Ok(FnDecl {
            name,
            params,
            body,
            line,
        })
    }

    fn block(&mut self) -> Result<Vec<Stmt>, CompileError> {
        self.enter()?;
        self.expect("{")?;
        let mut stmts = Vec::new();
        while !self.at("}") {
            if self.tok == Tok::Eof {
                return Err(self.err("unexpected end of input inside a block"));
            }
            stmts.push(self.statement()?);
        }
        self.expect("}")?;
        self.depth -= 1;
        Ok(stmts)
    }

    fn statement(&mut self) -> Result<Stmt, CompileError> {
        let line = self.line;
        if self.at_kw("let") {
            self.advance()?;
            let name = self.ident()?;
            self.expect("=")?;
            let value = self.expr()?;
            self.expect(";")?;
            return Ok(Stmt::Let(name, value, line));
        }
        if self.at_kw("if") {
            return self.if_statement();
        }
        if self.at_kw("while") {
            self.advance()?;
            let cond = self.expr()?;
            let body = self.block()?;
            return Ok(Stmt::While(cond, body));
        }
        if self.at_kw("return") {
            self.advance()?;
            if self.eat(";")? {
                return Ok(Stmt::Return(None));
            }
            let value = self.expr()?;
            self.expect(";")?;
            return Ok(Stmt::Return(Some(value)));
        }
        if self.at_kw("break") {
            self.advance()?;
            self.expect(";")?;
            return Ok(Stmt::Break(line));
        }
        if self.at_kw("continue") {
            self.advance()?;
            self.expect(";")?;
            return Ok(Stmt::Continue(line));
        }
        if self.at_kw("store") || self.at_kw("store8") {
            let width = if self.at_kw("store") {
                Width::W64
            } else {
                Width::W8
            };
            self.advance()?;
            self.expect("(")?;
            let addr = self.expr()?;
            self.expect(",")?;
            let value = self.expr()?;
            self.expect(")")?;
            self.expect(";")?;
            return Ok(Stmt::Store(addr, value, width));
        }

        let expr = self.expr()?;
        if self.at("=") {
            let Expr::Var(name) = expr else {
                return Err(self.err("only a variable can be assigned to"));
            };
            self.advance()?;
            let value = self.expr()?;
            self.expect(";")?;
            return Ok(Stmt::Assign(name, value, line));
        }
        self.expect(";")?;
        Ok(Stmt::Expr(expr))
    }

    fn if_statement(&mut self) -> Result<Stmt, CompileError> {
        self.enter()?;
        self.expect_kw("if")?;
        let cond = self.expr()?;
        let then_body = self.block()?;
        let else_body = if self.at_kw("else") {
            self.advance()?;
            if self.at_kw("if") {
                vec![self.if_statement()?]
            } else {
                self.block()?
            }
        } else {
            Vec::new()
        };
        self.depth -= 1;
        Ok(Stmt::If(cond, then_body, else_body))
    }

    fn expr(&mut self) -> Result<Expr, CompileError> {
        Ok(self.expr_with_height()?.0)
    }

    fn expr_with_height(&mut self) -> Result<(Expr, u32), CompileError> {
        self.enter()?;
        let result = self.binary(0);
        self.depth -= 1;
        result
    }

    /// Precedence climbing. Parser recursion grows with parentheses and with rising
    /// precedence, not with the number of precedence levels on every operand.
    fn binary(&mut self, min_prec: usize) -> Result<(Expr, u32), CompileError> {
        let (mut left, mut height) = self.unary()?;
        loop {
            let Tok::Punct(p) = self.tok else {
                return Ok((left, height));
            };
            let Some(prec) = precedence(p) else {
                return Ok((left, height));
            };
            if prec < min_prec {
                return Ok((left, height));
            }
            self.advance()?;
            let (right, right_height) = self.binary(prec + 1)?;
            height = self.grow(height.max(right_height))?;
            let (l, r) = (Box::new(left), Box::new(right));
            left = match p {
                "||" => Expr::LogicalOr(l, r),
                "&&" => Expr::LogicalAnd(l, r),
                "|" => Expr::Bin(BinOp::Or, l, r),
                "^" => Expr::Bin(BinOp::Xor, l, r),
                "&" => Expr::Bin(BinOp::And, l, r),
                "==" => Expr::Bin(BinOp::Eq, l, r),
                "!=" => Expr::Bin(BinOp::Ne, l, r),
                "<" => Expr::Bin(BinOp::Lt, l, r),
                "<=" => Expr::Bin(BinOp::Le, l, r),
                ">" => Expr::Bin(BinOp::Gt, l, r),
                ">=" => Expr::Bin(BinOp::Ge, l, r),
                "<<" => Expr::Bin(BinOp::Shl, l, r),
                ">>" => Expr::Bin(BinOp::Shr, l, r),
                ">>>" => Expr::Bin(BinOp::ShrU, l, r),
                "+" => Expr::Bin(BinOp::Add, l, r),
                "-" => Expr::Bin(BinOp::Sub, l, r),
                "*" => Expr::Bin(BinOp::Mul, l, r),
                "/" => Expr::Bin(BinOp::Div, l, r),
                "%" => Expr::Bin(BinOp::Rem, l, r),
                _ => return Err(self.err(format!("unknown operator `{p}`"))),
            };
        }
    }

    /// Height of a node whose tallest child has height `child`.
    fn grow(&self, child: u32) -> Result<u32, CompileError> {
        let height = child + 1;
        if height > MAX_EXPR_HEIGHT {
            return Err(self.err(format!(
                "expression is too deep (more than {MAX_EXPR_HEIGHT} levels)"
            )));
        }
        Ok(height)
    }

    fn unary(&mut self) -> Result<(Expr, u32), CompileError> {
        for (p, op) in [("-", UnOp::Neg), ("!", UnOp::Not), ("~", UnOp::BitNot)] {
            if self.at(p) {
                self.enter()?;
                self.advance()?;
                let (inner, height) = self.unary()?;
                self.depth -= 1;
                return Ok((Expr::Un(op, Box::new(inner)), self.grow(height)?));
            }
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<(Expr, u32), CompileError> {
        match self.tok.clone() {
            Tok::Int(value) => {
                self.advance()?;
                Ok((Expr::Int(value), 1))
            }
            Tok::Punct("(") => {
                self.advance()?;
                let inner = self.expr_with_height()?;
                self.expect(")")?;
                Ok(inner)
            }
            Tok::Ident(name) if name == "load" || name == "load8" => {
                let width = if name == "load" {
                    Width::W64
                } else {
                    Width::W8
                };
                self.advance()?;
                self.expect("(")?;
                let (addr, height) = self.expr_with_height()?;
                self.expect(")")?;
                Ok((Expr::Load(Box::new(addr), width), self.grow(height)?))
            }
            Tok::Ident(name) if name == "mem_size" => {
                self.advance()?;
                self.expect("(")?;
                self.expect(")")?;
                Ok((Expr::MemSize, 1))
            }
            Tok::Ident(name) => {
                if is_keyword(&name) {
                    return Err(self.err(format!("`{name}` is a reserved word")));
                }
                let line = self.line;
                self.advance()?;
                if !self.at("(") {
                    return Ok((Expr::Var(name), 1));
                }
                self.advance()?;
                let mut args = Vec::new();
                let mut height = 0;
                while !self.at(")") {
                    let (arg, arg_height) = self.expr_with_height()?;
                    args.push(arg);
                    height = height.max(arg_height);
                    if !self.eat(",")? {
                        break;
                    }
                }
                self.expect(")")?;
                Ok((Expr::Call(name, args, line), self.grow(height)?))
            }
            other => Err(self.err(format!("expected an expression, found {other:?}"))),
        }
    }
}

fn precedence(op: &str) -> Option<usize> {
    Some(match op {
        "||" => 0,
        "&&" => 1,
        "|" => 2,
        "^" => 3,
        "&" => 4,
        "==" | "!=" => 5,
        "<" | "<=" | ">" | ">=" => 6,
        "<<" | ">>" | ">>>" => 7,
        "+" | "-" => 8,
        "*" | "/" | "%" => 9,
        _ => return None,
    })
}

fn is_keyword(s: &str) -> bool {
    matches!(
        s,
        "fn" | "let"
            | "if"
            | "else"
            | "while"
            | "return"
            | "break"
            | "continue"
            | "store"
            | "store8"
            | "load"
            | "load8"
            | "mem_size"
    )
}
