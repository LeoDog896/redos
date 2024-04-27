use crate::ir::{Expr, ExprNode, IrAssertion};

/// Represents the result of an ILQ scan
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NqReturn {
    /// Whether the regex contains an ilq vulnerability
    pub is_present: bool,
}

impl NqReturn {
    /// Creates a new IlqReturn
    fn new(is_present: bool) -> Self {
        Self { is_present }
    }
}

/// Scans a regex tree for an nested quantifier 'vulnerability'.
/// Assumes `expr` is the root expression of the tree.
///
/// The regex must match the pattern (where t is arbitrary matchable tokens):
/// t*(t*)*t+
pub fn scan_nq(expr: &ExprNode) -> NqReturn {
    match &expr.current {
        Expr::Token(_) => NqReturn::new(false),
        Expr::Assertion(_) => NqReturn::new(false),
        Expr::Alt(list) => list.iter().fold(NqReturn::new(false), |acc, e| {
            if acc.is_present {
                acc
            } else {
                scan_nq(e)
            }
        }),
        // TODO: proper support for lookarounds
        Expr::LookAround(e, _) => scan_nq(e),
        // TODO: proper support for atomic groups
        Expr::AtomicGroup(e) => scan_nq(e),
        Expr::Group(e, _) => scan_nq(e),
        Expr::Optional(e) => scan_nq(e),
        Expr::Conditional { false_branch, .. } => scan_nq(false_branch),
        Expr::Repeat(e) => scan_nq(e),
        Expr::Concat(expr) => scan_concat(expr),
    }
}

fn scan_concat(exprs: &Vec<ExprNode>) -> Expr {
    for expr in exprs {}
}
