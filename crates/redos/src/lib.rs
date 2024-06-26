pub mod ir;
pub mod vulnerability;

mod ilq;
mod nq;

use fancy_regex::parse::Parser;
use fancy_regex::Expr as RegexExpr;
use ir::{to_expr, Expr, ExprConditional, ExprNode, StrongLink};
use vulnerability::{Vulnerability, VulnerabilityConfig};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegexInfo {
    pub has_repeat: bool,
    pub has_alternation: bool,
}

impl RegexInfo {
    fn merge(self, other: RegexInfo) -> RegexInfo {
        RegexInfo {
            has_repeat: self.has_repeat || other.has_repeat,
            has_alternation: self.has_alternation || other.has_alternation,
        }
    }

    fn empty() -> RegexInfo {
        RegexInfo {
            has_repeat: false,
            has_alternation: false,
        }
    }
}

/// Returns base information about regex
///
/// A regex must meet the following criteria to be even considered to be vulnerable:
/// - It must contain a repeat
/// - The repeat must have a bound size greater than `config.second_max_quantifier`
/// - The regex must have a terminating state (to allow for backtracking) (TODO: this is not implemented yet)
fn regex_pre_scan(expr: &StrongLink<ExprNode>) -> RegexInfo {
    match &expr.borrow().current {
        // even though there is a repeat, since it is the root node,
        // we must dig deeper to see if the repeat does matter,
        // since else this will violate our terminating state criteria
        Expr::Repeat(expr) => regex_pre_scan(expr),
        Expr::Token(_) => RegexInfo::empty(),
        Expr::Assertion(_) => RegexInfo::empty(),

        // propagate
        Expr::Concat(list) => list.iter().fold(RegexInfo::empty(), |acc, e| {
            acc.merge(regex_pre_scan_nested(e))
        }),

        // we use regex_pre_scan instead of nested because
        // the alternations effectively act as different regexes
        Expr::Alt(list) => list
            .iter()
            .fold(RegexInfo::empty(), |acc, e| acc.merge(regex_pre_scan(e)))
            .merge(RegexInfo {
                has_repeat: false,
                has_alternation: true,
            }),

        // doesn't matter how many groups we nest it in,
        // a group in the root node is as useful as
        // not having a group at all
        Expr::Group(e, _) => regex_pre_scan(e),
        Expr::LookAround(e, _) => regex_pre_scan(e),
        Expr::AtomicGroup(e) => regex_pre_scan(e),

        // if the optional is in the root, it doesn't matter
        // if it's nested or not, it will always match
        Expr::Optional(e) => regex_pre_scan(e),

        Expr::Conditional {
            condition,
            true_branch,
            false_branch,
        } => {
            match condition {
                // TODO: can we potentially skip the true_branch here if we know the group never matched
                ExprConditional::BackrefExistsCondition(_) => {
                    regex_pre_scan_nested(true_branch).merge(regex_pre_scan(false_branch))
                }
                ExprConditional::Condition(condition) => regex_pre_scan(condition)
                    .merge(regex_pre_scan_nested(true_branch))
                    .merge(regex_pre_scan_nested(false_branch)),
            }
        }
    }
}

fn regex_pre_scan_nested(expr: &StrongLink<ExprNode>) -> RegexInfo {
    match &expr.borrow().current {
        Expr::Repeat(_) => RegexInfo {
            has_repeat: true,
            has_alternation: false,
        },

        // no nested expressions
        Expr::Token(_) => RegexInfo::empty(),
        Expr::Assertion(_) => RegexInfo::empty(),

        // propagate
        Expr::Concat(list) => list.iter().fold(RegexInfo::empty(), |acc, e| {
            acc.merge(regex_pre_scan_nested(e))
        }),
        Expr::Alt(list) => list
            .iter()
            .fold(RegexInfo::empty(), |acc, e| {
                acc.merge(regex_pre_scan_nested(e))
            })
            .merge(RegexInfo {
                has_repeat: false,
                has_alternation: true,
            }),
        Expr::Group(e, _) => regex_pre_scan_nested(e),
        Expr::LookAround(e, _) => regex_pre_scan_nested(e),
        Expr::AtomicGroup(e) => regex_pre_scan_nested(e),
        Expr::Optional(e) => regex_pre_scan_nested(e),
        Expr::Conditional {
            condition,
            true_branch,
            false_branch,
        } => match condition {
            ExprConditional::BackrefExistsCondition(_) => RegexInfo::empty(),
            ExprConditional::Condition(condition) => regex_pre_scan_nested(condition)
                .merge(regex_pre_scan_nested(true_branch))
                .merge(regex_pre_scan_nested(false_branch)),
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

    /// The information about the regex
    pub regex_info: RegexInfo,
}

/// Returns the list of vulnerabilities in a regex
pub fn vulnerabilities(
    regex: &str,
    config: &VulnerabilityConfig,
) -> fancy_regex::Result<VulnerabilityResult> {
    // attempt to parse the regex with rust's regex parser
    let can_be_dfa = regex::Regex::new(regex).is_ok();

    // first pass: parse the regex
    let tree = Parser::parse(regex)?;

    if tree.expr == RegexExpr::Empty {
        return Ok(VulnerabilityResult {
            vulnerabilities: vec![],
            dfa: can_be_dfa,
            regex_info: RegexInfo::empty(),
        });
    }

    // second pass: turn AST into IR
    let expr = match to_expr(&tree.expr, config) {
        Some(expr) => expr,
        None => {
            return Ok(VulnerabilityResult {
                vulnerabilities: vec![],
                dfa: can_be_dfa,
                regex_info: RegexInfo::empty(),
            })
        }
    };

    // third pass: exit early if there are no repeats
    let regex_info = regex_pre_scan(&expr);
    if !regex_info.has_repeat {
        return Ok(VulnerabilityResult {
            vulnerabilities: vec![],
            dfa: can_be_dfa,
            regex_info,
        });
    }

    // scan for vulnerabilities
    {
        let mut vulnerabilities: Vec<Vulnerability> = vec![];

        // first vulnerability scan: ILQ
        if ilq::scan_ilq(expr.clone()).is_present {
            vulnerabilities.push(Vulnerability::InitialQuantifier);
        }

        // second vulnerability scan: NQ
        if nq::scan_nq(expr).is_present {
            vulnerabilities.push(Vulnerability::NestedQuantifier);
        }

        Ok(VulnerabilityResult {
            vulnerabilities,
            dfa: can_be_dfa,
            regex_info,
        })
    }
}
