use crate::ir::{Expr, IrAssertion};

/// Scans an ilq. Assumes `expr` is the root expression of the tree.
pub fn scan_ilq(expr: &Expr) -> bool {
    match expr {
        // if we hit anything that isn't a Vec<Expr>, we're done
        Expr::Token => false,
        Expr::Assertion(_) => false,
        
        Expr::Conditional { false_branch, .. } => scan_ilq_recursive(&false_branch).unwrap_or_else(|| false),

    }
}


/// Returns Some(true) iif an ilq is present anywhere in the regex.
/// Returns Some(false) iif no ilq is present anywhere in the regex.
/// 
/// Returns None if an ilq higher up in the recursive chain can continue
/// looking through its Vec<Expr>
fn scan_ilq_recursive(expr: &Expr) -> Option<bool> {
    match expr {
        // if we hit a non-complex non-optional expression, we can stop
        Expr::Token => Some(false),
        // if we hit an odd assertion, we can stop
        Expr::Assertion(assertion) => match assertion {
            // initial large quantifier requires that the quantifier is first.
            // if we hit this, it is not first
            IrAssertion::Start => Some(false),
            // odd that the end will be here, but regardless, not an ILQ
            IrAssertion::End => Some(false),
            // a word boundary linearizes any ilq
            IrAssertion::WordBoundary => Some(false),
            // TODO
            _ => None
        }
        // explore every potential path for some ilq
        Expr::Alt(list) => list.iter().find(|expr| scan_ilq(expr) == Some(false)),
        // TODO
        _ => None,
    }
}
