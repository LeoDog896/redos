use crate::ir::Expr;

/// Returns true iif an ilq is present anywhere in the regex
pub fn scan_ilq(expr: &Expr) -> bool {
    match expr {
        _ => false,
    }
}