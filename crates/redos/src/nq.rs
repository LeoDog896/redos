use std::rc::Rc;

use crate::{
    find_node_type,
    ir::{Expr, ExprNode, ExprWalker},
};

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
pub fn scan_nq(expr: Rc<ExprNode>) -> NqReturn {
    match &expr.current {
        Expr::Token(_) => NqReturn::new(false),
        Expr::Assertion(_) => NqReturn::new(false),
        Expr::Alt(list) => list.iter().fold(NqReturn::new(false), |acc, e| {
            if acc.is_present {
                acc
            } else {
                scan_nq(e.clone())
            }
        }),
        // TODO: proper support for lookarounds
        Expr::LookAround(e, _) => scan_nq(e.clone()),
        // TODO: proper support for atomic groups
        Expr::AtomicGroup(e) => scan_nq(e.clone()),
        Expr::Group(e, _) => scan_nq(e.clone()),
        Expr::Optional(e) => scan_nq(e.clone()),
        Expr::Conditional { false_branch, .. } => scan_nq(false_branch.clone()),
        Expr::Repeat(e) => scan_nq(e.clone()),
        Expr::Concat(_) => scan_concat(&expr),
    }
}

fn scan_concat(expr: &Rc<ExprNode>) -> NqReturn {
    // find the initial repeat node
    let repeat_node = find_node_type!(expr.clone(), Repeat);

    if repeat_node.is_none() {
        return NqReturn::new(false);
    }

    let repeat_node = repeat_node.unwrap();

    // find the second, nested repeat node
    let nested_repeat = find_node_type!(repeat_node, Repeat, always_ancestor = repeat_node);

    if nested_repeat.is_none() {
        return NqReturn::new(false);
    }

    let nested_repeat = nested_repeat.unwrap();

    // make sure there exists a required token we can match somewhere
    let final_token = find_node_type!(
        nested_repeat,
        Token,
        always_ancestor = expr,
        never_ancestor_type_sandwich = Optional
    );

    NqReturn::new(final_token.is_some())
}
