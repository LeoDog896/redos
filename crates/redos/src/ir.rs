//! Intermediate representation of a regular expression.
//! Used to simplify the AST and make it easier to work with.

use std::num::NonZeroUsize;

use fancy_regex::{Assertion, Expr as RegexExpr, LookAround};

use crate::vulnerability::VulnerabilityConfig;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum IrAssertion {
    /// Start of input text
    Start,
    /// End of input text
    End,
    /// Left word boundary
    LeftWordBoundary,
    /// Right word boundary
    RightWordBoundary,
    /// Both word boundaries
    WordBoundary,
    /// Not word boundary
    NotWordBoundary,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ExprConditional {
    Condition(Box<Expr>),
    BackrefExistsCondition(usize),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Expr {
    /// Some token, whether its a character class, any character, etc.
    Token,
    /// An assertion
    Assertion(IrAssertion),
    /// Concatenation of multiple expressions, must match in order, e.g. `a.` is a concatenation of
    /// the literal `a` and `.` for any character
    Concat(Vec<Expr>),
    /// Alternative of multiple expressions, one of them must match, e.g. `a|b` is an alternative
    /// where either the literal `a` or `b` must match
    Alt(Vec<Expr>),
    /// Capturing group of expression, e.g. `(a.)` matches `a` and any character and "captures"
    /// (remembers) the match
    ///
    /// The usize is the number of the capturing group, starting from 1
    Group(Box<Expr>, usize),
    /// Look-around (e.g. positive/negative look-ahead or look-behind) with an expression, e.g.
    /// `(?=a)` means the next character must be `a` (but the match is not consumed)
    LookAround(Box<Expr>, LookAround),
    /// Some large repeat of an expression.
    // Implementation Note: Greedy does not matter as if it doesn't match (in the case of ReDoS abuse),
    // greedy will not affect its matching because of the terminal token.
    Repeat(Box<Expr>),
    /// Optional expression, e.g. `a?` means `a` is optional
    Optional(Box<Expr>),
    /// Atomic non-capturing group, e.g. `(?>ab|a)` in text that contains `ab` will match `ab` and
    /// never backtrack and try `a`, even if matching fails after the atomic group.
    AtomicGroup(Box<Expr>),
    /// If/Then/Else Condition. If there is no Then/Else, these will just be empty expressions.
    Conditional {
        /// The conditional expression to evaluate
        condition: ExprConditional,
        /// What to execute if the condition is true
        true_branch: Box<Expr>,
        /// What to execute if the condition is false
        false_branch: Box<Expr>,
    },
}

/// Converts a fancy-regex AST to an IR AST
pub fn to_expr(
    expr: &RegexExpr,
    config: &VulnerabilityConfig,
    group_increment: NonZeroUsize,
) -> Option<Expr> {
    match expr {
        RegexExpr::Empty => None,
        RegexExpr::Any { .. } => Some(Expr::Token),
        RegexExpr::Assertion(a) => Some(Expr::Assertion(match a {
            // Since start and line only depend on the multiline flag,
            // they don't particurally matter for ReDoS detection.
            Assertion::StartText => IrAssertion::Start,
            Assertion::EndText => IrAssertion::End,
            Assertion::StartLine { .. } => IrAssertion::Start,
            Assertion::EndLine { .. } => IrAssertion::End,

            Assertion::LeftWordBoundary => IrAssertion::LeftWordBoundary,
            Assertion::RightWordBoundary => IrAssertion::RightWordBoundary,
            Assertion::WordBoundary => IrAssertion::WordBoundary,
            Assertion::NotWordBoundary => IrAssertion::NotWordBoundary,
        })),
        RegexExpr::Literal { .. } => Some(Expr::Token),
        // TODO: propagate group increment
        RegexExpr::Concat(list) => Some(Expr::Concat(
            list.iter()
                .filter_map(|e| to_expr(e, config, group_increment))
                .collect(),
        )),
        RegexExpr::Alt(list) => Some(Expr::Alt(
            list.iter()
                .filter_map(|e| to_expr(e, config, group_increment))
                .collect(),
        )),
        RegexExpr::Group(e) => to_expr(
            e,
            config,
            group_increment
                .checked_add(1)
                .expect("group increment overflow"),
        )
        .map(|e| Expr::Group(Box::new(e), group_increment.into())),
        RegexExpr::LookAround(e, la) => {
            to_expr(e, config, group_increment).map(|e| Expr::LookAround(Box::new(e), *la))
        }
        RegexExpr::Repeat {
            child,
            lo,
            hi,
            greedy: _,
        } => {
            let range = hi - lo;

            let expression = to_expr(child, config, group_increment);
            let expression = if range > config.four_max_quantifier {
                expression.map(|child| Expr::Repeat(Box::new(child)))
            } else {
                expression
            };

            if *lo == 0 {
                expression.map(|e| Expr::Optional(Box::new(e)))
            } else {
                expression
            }
        }
        // Delegates essentially forcibly match some string, so we can turn them into a token
        RegexExpr::Delegate { .. } => Some(Expr::Token),
        // note that since we convert backrefs to tokens, the complexity of a vulnerability
        // may underestimate the actual complexity, though this will not cause
        // false negatives
        RegexExpr::Backref(_) => Some(Expr::Token),
        RegexExpr::AtomicGroup(e) => {
            to_expr(e, config, group_increment).map(|e| Expr::AtomicGroup(Box::new(e)))
        }
        RegexExpr::KeepOut => None,
        RegexExpr::ContinueFromPreviousMatchEnd => None,
        RegexExpr::BackrefExistsCondition(_) => None,
        RegexExpr::Conditional {
            condition,
            true_branch,
            false_branch,
        } => {
            let true_branch = to_expr(true_branch, config, group_increment);
            let false_branch = to_expr(false_branch, config, group_increment);
            if let (Some(true_branch), Some(false_branch)) = (true_branch, false_branch) {
                let condition: Option<ExprConditional> = match condition.as_ref() {
                    &RegexExpr::BackrefExistsCondition(number) => {
                        Some(ExprConditional::BackrefExistsCondition(number))
                    }
                    expr => to_expr(expr, config, group_increment)
                        .map(|x| ExprConditional::Condition(Box::new(x))),
                };

                condition.map(|condition| Expr::Conditional {
                    condition,
                    true_branch: Box::new(true_branch),
                    false_branch: Box::new(false_branch),
                })
            } else {
                None
            }
        }
    }
}
