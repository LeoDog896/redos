//! Immediate representation of a regular expression.
//! Used to simplify the AST and make it easier to work with.

use fancy_regex::{Assertion, Expr as RegexExpr, LookAround};

use crate::vulnerability::VulnerabilityConfig;

#[derive(Debug, PartialEq, Eq)]
pub enum ExprConditional {
    Condition(Box<Expr>),
    BackrefExistsCondition(usize),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Expr {
    /// Some token, whether its a character class, any character, etc.
    Token,
    /// An assertion
    Assertion(Assertion),
    /// Concatenation of multiple expressions, must match in order, e.g. `a.` is a concatenation of
    /// the literal `a` and `.` for any character
    Concat(Vec<Expr>),
    /// Alternative of multiple expressions, one of them must match, e.g. `a|b` is an alternative
    /// where either the literal `a` or `b` must match
    Alt(Vec<Expr>),
    /// Capturing group of expression, e.g. `(a.)` matches `a` and any character and "captures"
    /// (remembers) the match
    Group(Box<Expr>),
    /// Look-around (e.g. positive/negative look-ahead or look-behind) with an expression, e.g.
    /// `(?=a)` means the next character must be `a` (but the match is not consumed)
    LookAround(Box<Expr>, LookAround),
    /// Repeat of an expression, e.g. `a*` or `a+` or `a{1,3}`
    Repeat {
        /// The expression that is being repeated
        child: Box<Expr>,
        /// Greedy means as much as possible is matched, e.g. `.*b` would match all of `abab`.
        /// Non-greedy means as little as possible, e.g. `.*?b` would match only `ab` in `abab`.
        greedy: bool,
    },
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
pub fn to_expr(expr: &RegexExpr, config: &VulnerabilityConfig) -> Option<Expr> {
    match expr {
        RegexExpr::Empty => None,
        RegexExpr::Any { .. } => Some(Expr::Token),
        RegexExpr::Assertion(a) => Some(Expr::Assertion(*a)),
        RegexExpr::Literal { .. } => Some(Expr::Token),
        RegexExpr::Concat(list) => Some(Expr::Concat(
            list.iter()
                .filter_map(|e| to_expr(e, config))
                .collect(),
        )),
        RegexExpr::Alt(list) => Some(Expr::Alt(
            list.iter()
                .filter_map(|e| to_expr(e, config))
                .collect(),
        )),
        RegexExpr::Group(e) => to_expr(e, config).map(|e| Expr::Group(Box::new(e))),
        RegexExpr::LookAround(e, la) => {
            to_expr(e, config).map(|e| Expr::LookAround(Box::new(e), *la))
        }
        RegexExpr::Repeat {
            child,
            lo,
            hi,
            greedy,
        } => {
            let range = hi - lo;

            let expression = if range > config.max_quantifier {
                to_expr(child, config).map(|child| Expr::Repeat {
                    child: Box::new(child),
                    greedy: *greedy,
                })
            } else {
                to_expr(child, config)
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
            to_expr(e, config).map(|e| Expr::AtomicGroup(Box::new(e)))
        }
        RegexExpr::KeepOut => None,
        RegexExpr::ContinueFromPreviousMatchEnd => None,
        RegexExpr::BackrefExistsCondition(_) => None,
        RegexExpr::Conditional {
            condition,
            true_branch,
            false_branch,
        } => {
            let true_branch = to_expr(true_branch, config);
            let false_branch = to_expr(false_branch, config);
            if let (Some(true_branch), Some(false_branch)) =
                (true_branch, false_branch)
            {
                let condition: Option<ExprConditional> = match condition.as_ref() {
                    &RegexExpr::BackrefExistsCondition(number) => Some(ExprConditional::BackrefExistsCondition(number)),
                    expr => to_expr(expr, config).map(|x| ExprConditional::Condition(Box::new(x)))
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
