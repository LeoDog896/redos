mod ir;
pub mod vulnerability;

use fancy_regex::parse::Parser;
use fancy_regex::Result;
use ir::{to_expr, Expr};
use vulnerability::{Vulnerability, VulnerabilityConfig};

/// Returns true iif repeats are present anywhere in the regex
///
/// A regex must meet the following criteria to be even considered to be vulnerable:
/// - It must contain a repeat
/// - The repeat must have a bound size greater than `config.max_quantifier`
/// - The regex must have a terminating state (to allow for backtracking) (TODO: this is not implemented yet)
fn repeats_anywhere(expr: &Expr, config: &VulnerabilityConfig) -> bool {
    match expr {
        Expr::Repeat { lo, hi, .. } => {
            // if the bound is large, return true
            return hi - lo > config.max_quantifier;
        }

        // no nested expressions
        Expr::Empty => false,
        Expr::Token => false,
        Expr::Assertion(_) => false,
        Expr::ContinueFromPreviousMatchEnd => false,
        Expr::BackrefExistsCondition(_) => false,

        // propagate
        Expr::Concat(list) => list.iter().any(|e| repeats_anywhere(e, config)),
        Expr::Alt(list) => list.iter().any(|e| repeats_anywhere(e, config)),
        Expr::Group(e) => repeats_anywhere(e.as_ref(), config),
        Expr::LookAround(e, _) => repeats_anywhere(e.as_ref(), config),
        Expr::AtomicGroup(e) => repeats_anywhere(e.as_ref(), config),
        Expr::Conditional {
            condition,
            true_branch,
            false_branch,
        } => {
            repeats_anywhere(condition.as_ref(), config)
                || repeats_anywhere(true_branch.as_ref(), config)
                || repeats_anywhere(false_branch.as_ref(), config)
        }
    }
}

/// The result of a vulnerability check
#[derive(Debug, PartialEq, Eq)]
pub struct VulnerabilityResult {
    /// The list of vulnerabilities found
    pub vulnerabilities: Vec<Vulnerability>,

    /// If this regex can be reduced to a DFA
    pub dfa: bool,
}

/// Returns the list of vulnerabilities in a regex
pub fn vulnerabilities(regex: &str, config: &VulnerabilityConfig) -> Result<VulnerabilityResult> {
    // attempt to parse the regex with rust's regex parser
    let can_be_dfa = regex::Regex::new(regex).is_ok();

    // first pass: parse the regex
    let tree = Parser::parse(regex)?;

    // second pass: turn AST into IR
    let expr = to_expr(&tree, &tree.expr).expect("Failed to convert AST to IR; this is a bug");

    // third pass: exit early if there are no repeats
    if !repeats_anywhere(&expr, config) {
        return Ok(VulnerabilityResult {
            vulnerabilities: vec![],
            dfa: can_be_dfa,
        });
    }

    // TODO: this is a fake placeholder
    Ok(VulnerabilityResult {
        vulnerabilities: vec![Vulnerability::ExponentialOverlappingDisjunction],
        dfa: can_be_dfa,
    })
}
