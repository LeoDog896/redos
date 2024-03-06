pub mod ir;
pub mod vulnerability;

mod ilq;

use fancy_regex::parse::Parser;
use fancy_regex::{Expr as RegexExpr, Result};
use ir::{to_expr, Expr, ExprConditional};
use vulnerability::{Vulnerability, VulnerabilityConfig};

/// Returns true iif repeats are present anywhere in the regex
///
/// A regex must meet the following criteria to be even considered to be vulnerable:
/// - It must contain a repeat
/// - The repeat must have a bound size greater than `config.max_quantifier`
/// - The regex must have a terminating state (to allow for backtracking) (TODO: this is not implemented yet)
fn repeats_anywhere(expr: &Expr) -> bool {
    match expr {
        Expr::Repeat { .. } => true,

        // no nested expressions
        Expr::Token => false,
        Expr::Assertion(_) => false,

        // propagate
        Expr::Concat(list) => list.iter().any(repeats_anywhere),
        Expr::Alt(list) => list.iter().any(repeats_anywhere),
        Expr::Group(e, _) => repeats_anywhere(e.as_ref()),
        Expr::LookAround(e, _) => repeats_anywhere(e.as_ref()),
        Expr::AtomicGroup(e) => repeats_anywhere(e.as_ref()),
        Expr::Optional(e) => repeats_anywhere(e.as_ref()),
        Expr::Conditional {
            condition,
            true_branch,
            false_branch,
        } => match condition {
            ExprConditional::BackrefExistsCondition(_) => false,
            ExprConditional::Condition(condition) => {
                repeats_anywhere(condition.as_ref())
                    || repeats_anywhere(true_branch.as_ref())
                    || repeats_anywhere(false_branch.as_ref())
            }
        },
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

    if tree.expr == RegexExpr::Empty {
        return Ok(VulnerabilityResult {
            vulnerabilities: vec![],
            dfa: can_be_dfa,
        });
    }

    // second pass: turn AST into IR
    let expr = to_expr(&tree.expr, config, nonzero_lit::usize!(1))
        .expect("Failed to convert AST to IR; this is a bug");

    // third pass: exit early if there are no repeats
    if !repeats_anywhere(&expr) {
        return Ok(VulnerabilityResult {
            vulnerabilities: vec![],
            dfa: can_be_dfa,
        });
    }

    // TODO: this is a fake placeholder
    Ok(VulnerabilityResult {
        vulnerabilities: vec![Vulnerability::InitialQuantifier],
        dfa: can_be_dfa,
    })
}
