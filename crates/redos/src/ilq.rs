use crate::ir::Expr;

/// Returns true iif an ilq is present anywhere in the regex
pub fn scan_ilq(expr: &Expr) -> bool {
    match expr {
        // if we hit a non-complex non-optional expression, we can stop
        Expr::Token => false,
        // explore every potential path for some ilq
        Expr::Alt(list) => list.iter().any(scan_ilq),
        // TODO
        _ => false,
    }
}
