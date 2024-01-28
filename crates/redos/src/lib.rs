pub mod vulnerability;

use fancy_regex::parse::Parser;
use fancy_regex::{Expr, Result};
use vulnerability::Vulnerability;

pub fn repeats_anywhere(expr: &Expr) -> bool {
    match expr {
        Expr::Empty => false,
        Expr::Any { .. } => false,
        Expr::Assertion(_) => false,
        Expr::Literal { .. } => false,
        Expr::Concat(list) => list.iter().any(repeats_anywhere),
        Expr::Alt(list) => list.iter().any(repeats_anywhere),
        Expr::Group(e) => repeats_anywhere(e.as_ref()),
        Expr::LookAround(e, _) => repeats_anywhere(e.as_ref()),
        Expr::Repeat { .. } => true,
        Expr::Delegate { .. } => false,
        Expr::Backref(_) => false,
        Expr::AtomicGroup(e) => repeats_anywhere(e.as_ref()),
        Expr::KeepOut => false,
        Expr::ContinueFromPreviousMatchEnd => false,
        Expr::BackrefExistsCondition(_) => false,
        Expr::Conditional { condition, true_branch, false_branch } => {
            repeats_anywhere(condition.as_ref())
                || repeats_anywhere(true_branch.as_ref())
                || repeats_anywhere(false_branch.as_ref())
        },
    }
}

/// Returns the list of vulnerabilities in a regex
pub fn vulnerabilities(regex: &str) -> Result<Vec<Vulnerability>> {
    // search for vulnerable quantifiers - +, *, `{`
    let tree = Parser::parse(regex)?;

    if !repeats_anywhere(&tree.expr) {
        return Ok(vec![]);
    }

    // TODO: this is a fake placeholder
    Ok(vec![Vulnerability::ExponentialOverlappingDisjunction])
}
