pub mod vulnerability;

use fancy_regex::parse::Parser;
use fancy_regex::{Expr, Result};
use vulnerability::Vulnerability;

#[derive(Debug)]
pub struct VulnerabilityConfig {
    /// The max size an upper bound can be before it is considered "large"
    pub max_quantifier: usize,
}

impl Default for VulnerabilityConfig {
    fn default() -> Self {
        Self {
            max_quantifier: 100,
        }
    }
}

/// Returns true iif repeats are present anywhere in the regex
fn repeats_anywhere(expr: &Expr, config: &VulnerabilityConfig) -> bool {
    match expr {
        // if found, return true
        Expr::Repeat { lo, hi, .. } => {
            // if the bound is large, return true
            return hi - lo > config.max_quantifier
        }

        // no nested expressions
        Expr::Empty => false,
        Expr::Any { .. } => false,
        Expr::Assertion(_) => false,
        Expr::Literal { .. } => false,
        Expr::Delegate { .. } => false,
        Expr::Backref(_) => false,
        Expr::KeepOut => false,
        Expr::ContinueFromPreviousMatchEnd => false,
        Expr::BackrefExistsCondition(_) => false,

        // propagate
        Expr::Concat(list) => list.iter().any(|e| repeats_anywhere(e, config)),
        Expr::Alt(list) => list.iter().any(|e| repeats_anywhere(e, config)),
        Expr::Group(e) => repeats_anywhere(e.as_ref(), config),
        Expr::LookAround(e, _) => repeats_anywhere(e.as_ref(), config),
        Expr::AtomicGroup(e) => repeats_anywhere(e.as_ref(), config),
        Expr::Conditional { condition, true_branch, false_branch } => {
            repeats_anywhere(condition.as_ref(), config)
                || repeats_anywhere(true_branch.as_ref(), config)
                || repeats_anywhere(false_branch.as_ref(), config)
        },
    }
}

/// Returns the list of vulnerabilities in a regex
pub fn vulnerabilities(regex: &str, config: &VulnerabilityConfig) -> Result<Vec<Vulnerability>> {
    // search for vulnerable quantifiers - +, *, `{`
    let tree = Parser::parse(regex)?;

    // exit early if there are no repeats
    if !repeats_anywhere(&tree.expr, config) {
        return Ok(vec![]);
    }

    // TODO: this is a fake placeholder
    Ok(vec![Vulnerability::ExponentialOverlappingDisjunction])
}
