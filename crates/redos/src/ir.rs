//! Intermediate representation of a regular expression.
//! Used to simplify the AST and make it easier to work with.

use std::{num::NonZeroUsize, rc::Rc};

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
    Condition(Box<ExprNode>),
    BackrefExistsCondition(usize),
}

fn option_rc<T>(option: Option<T>) -> Option<Rc<T>> {
    option.map(|x| Rc::new(x))
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ExprNode {
    current: Expr,
    previous: Option<Rc<ExprNode>>,
    next: Option<Rc<ExprNode>>,
    parent: Option<Rc<ExprNode>>,
}

impl ExprNode {
    /// Helper function that creates a new node for the IR generation
    fn new_prev(current: Expr, previous: Option<ExprNode>, parent: Option<ExprNode>) -> ExprNode {
        ExprNode {
            current,
            previous: option_rc(previous),
            next: None,
            parent: option_rc(parent),
        }
    }

    /// Helper function that creates a new node for the IR generation,
    /// allowing consuming itself to reparent its child expressions.
    fn new_prev_consume_optional<F>(
        current: F,
        previous: Option<ExprNode>,
        parent: Option<ExprNode>,
    ) -> Option<ExprNode> where F: FnOnce(&ExprNode) -> Option<Expr> {
        // Here, we don't care about current; we are going to replace it
        let mut node = ExprNode::new_prev(Expr::Concat(vec![]), previous, parent);

        let child = current(&node);

        if child.is_none() {
            return None
        }

        node.current = child.unwrap();

        Some(node)
    }

    fn new_prev_consume<F>(
        current: F,
        previous: Option<ExprNode>,
        parent: Option<ExprNode>
    ) -> ExprNode where F: FnOnce(&ExprNode) -> Expr {
        Self::new_prev_consume_optional(|x| Some(current(x)), previous, parent).unwrap()
    }

    /// Helper function that produces a dummy value
    fn dummy() -> ExprNode {
        ExprNode {
            current: Expr::Token(Token {
                yes: vec![],
                no: vec![],
                ignore_case: false
            }),
            previous: None,
            next: None,
            parent: None,
        }
    }

    fn parented_dummy(parent: Option<ExprNode>, previous: Option<ExprNode>) -> ExprNode {
        ExprNode {
            current: Expr::Token(Token {
                yes: vec![],
                no: vec![],
                ignore_case: false
            }),
            previous: option_rc(previous),
            next: None,
            parent: option_rc(parent),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Value {
    Singular(String),
    Range(String, String),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Token {
    /// Singular tokens that can be matched in this token
    yes: Vec<Value>,
    /// Singular tokens that can't be matched in this token
    no: Vec<Value>,
    /// Whether comparisons care about ignoring case
    ignore_case: bool
}

impl Token {
    /// Creates a new token.
    /// Takes in a basic regex that is either a single character
    /// or a character class.
    fn new(regex: &str) -> Token {
        Self::new_case(regex, false)
    }

    fn new_case(regex: &str, ignore_case: bool) -> Token {
        if !(regex.contains('[') || regex.contains(']')) {
            // This isn't a character class - just a single character
            Token {
                yes: vec![Value::Singular(regex.to_string())],
                no: vec![],
                ignore_case
            }
        } else {
            unimplemented!("No support for parsing character classes yet.")
        }
    }

    fn overlaps(&self, token: &Token) -> bool {
        unimplemented!("Can not detect overlapping tokens yet.")
    }
}

fn container<F>(
    previous: Option<ExprNode>,
    parent: Option<ExprNode>,
    group_increment: NonZeroUsize,
    config: &VulnerabilityConfig,
    expr: &RegexExpr,
    gen: F
) -> Option<ExprNode> where F: FnOnce(Option<ExprNode>) -> Expr {
    let mut node = ExprNode::new_prev(
        Expr::Group(Box::new(ExprNode::dummy()), group_increment.into()),
        previous,
        parent,
    );

    let nest = to_nested_expr(
        expr,
        config,
        group_increment
            .checked_add(1)
            .expect("group increment overflow"),
        Some(node.clone()), // TODO: expensive clone
        Some(node.clone()),
    );

    if nest.is_none() {
        return None;
    }

    node.current = gen(nest);

    Some(node)
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Expr {
    /// Some token, whether its a character class, any character, etc.
    Token(Token),
    /// An assertion
    Assertion(IrAssertion),
    /// Concatenation of multiple expressions, must match in order, e.g. `a.` is a concatenation of
    /// the literal `a` and `.` for any character
    Concat(Vec<ExprNode>),
    /// Alternative of multiple expressions, one of them must match, e.g. `a|b` is an alternative
    /// where either the literal `a` or `b` must match
    Alt(Vec<ExprNode>),
    /// Capturing group of expression, e.g. `(a.)` matches `a` and any character and "captures"
    /// (remembers) the match
    ///
    /// The usize is the number of the capturing group, starting from 1
    Group(Box<ExprNode>, usize),
    /// Look-around (e.g. positive/negative look-ahead or look-behind) with an expression, e.g.
    /// `(?=a)` means the next character must be `a` (but the match is not consumed)
    LookAround(Box<ExprNode>, LookAround),
    /// Some large repeat of an expression.
    // Implementation Note: Greedy does not matter as if it doesn't match (in the case of ReDoS abuse),
    // greedy will not affect its matching because of the terminal token.
    Repeat(Box<ExprNode>),
    /// Optional expression, e.g. `a?` means `a` is optional
    Optional(Box<ExprNode>),
    /// Atomic non-capturing group, e.g. `(?>ab|a)` in text that contains `ab` will match `ab` and
    /// never backtrack and try `a`, even if matching fails after the atomic group.
    AtomicGroup(Box<ExprNode>),
    /// If/Then/Else Condition. If there is no Then/Else, these will just be empty expressions.
    Conditional {
        /// The conditional expression to evaluate
        condition: ExprConditional,
        /// What to execute if the condition is true
        true_branch: Box<ExprNode>,
        /// What to execute if the condition is false
        false_branch: Box<ExprNode>,
    },
}

pub fn to_expr(expr: &RegexExpr, config: &VulnerabilityConfig) -> Option<ExprNode> {
    to_nested_expr(expr, config, nonzero_lit::usize!(1), None, None)
        .map(normalize)
}

fn normalize(expr: ExprNode) -> ExprNode {
    expr
}

fn to_nested_expr(
    expr: &RegexExpr,
    config: &VulnerabilityConfig,
    group_increment: NonZeroUsize,
    parent: Option<ExprNode>,
    previous: Option<ExprNode>,
) -> Option<ExprNode> {
    match expr {
        RegexExpr::Empty => None,
        RegexExpr::Any { newline } => Some(ExprNode::new_prev(
            Expr::Token(if *newline {
                Token::new(".")
            } else {
                Token {
                    yes: vec![Value::Singular(".".to_string())],
                    no: vec![Value::Singular("\\n".to_string())],
                    ignore_case: false
                }
            }),
            previous,
            parent,
        )),
        RegexExpr::Assertion(a) => Some(ExprNode::new_prev(
            Expr::Assertion(match a {
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
            }),
            previous,
            parent,
        )),
        RegexExpr::Literal { casei, val } => Some(ExprNode::new_prev(
            Expr::Token(if *casei {
                Token::new_case(val, true)
            } else {
                Token::new(val)
            }),
            previous,
            parent,
        )),
        // TODO: propagate group increment
        RegexExpr::Concat(list) => ExprNode::new_prev_consume_optional(|parent| {
            let no_siblings_list = list.iter()
                .filter_map(|e| to_nested_expr(e, config, group_increment, Some(parent.clone()), None))
                .collect::<Vec<_>>();

            let nodes = no_siblings_list.iter()
                .enumerate()
                .map(|(i, e)| {
                    let previous = if i == 0 {
                        parent.clone()
                    } else {
                        no_siblings_list[i].clone()
                    };

                    let e = e.clone();

                    ExprNode {
                        current: e.current,
                        previous: Some(previous.into()),
                        next: e.next,
                        parent: e.parent,
                    }
                })
                .collect::<Vec<_>>();

            if nodes.is_empty() {
                return None;
            }

            Some(Expr::Concat(nodes))
        }, previous, parent),
        RegexExpr::Alt(list) => {
            let mut alt_expr_node = ExprNode::new_prev(Expr::Alt(vec![]), previous, parent);

            let list = list.iter()
                .filter_map(|e| to_nested_expr(e, config, group_increment, Some(alt_expr_node.clone()), Some(alt_expr_node.clone())))
                .collect();

            alt_expr_node.current = Expr::Alt(list);

            Some(alt_expr_node)
        },
        RegexExpr::Group(e) => {
            container(previous, parent, group_increment, config, e, |tree: Option<ExprNode>| {
                Expr::Group(
                    Box::new(tree.unwrap()), group_increment.into()
                )
            })
        }
        RegexExpr::LookAround(e, la) => {
            container(previous, parent, group_increment, config, e, |tree: Option<ExprNode>| {
                Expr::LookAround(
                    Box::new(tree.unwrap()), *la
                )
            })
        }
        RegexExpr::Repeat {
            child,
            lo,
            hi,
            greedy: _,
        } => {
            let range = hi - lo;

            let is_complex = range > config.four_max_quantifier || *lo != 0;

            if !is_complex {
                return to_nested_expr(child, config, group_increment, parent, previous);
            }

            ExprNode::new_prev_consume_optional(|node| {
                let repeat_node = if range > config.four_max_quantifier {
                    ExprNode::new_prev_consume_optional(|node| {
                        to_nested_expr(child.to_owned(), config, group_increment, Some(node.clone()), Some(node.clone()))
                            .map(|x| Expr::Repeat(Box::new(x)))
                    }, Some(node.clone()), Some(node.clone()))
                } else {
                    to_nested_expr(child, config, group_increment, Some(node.clone()), Some(node.clone()))
                };

                if repeat_node.is_none() {
                    return None;
                }
                
                if *lo == 0 {
                   Some(Expr::Optional(Box::new(repeat_node.unwrap())))
                } else {
                    panic!("Should have been covered by is_complex case");
                }
            }, previous, parent)
        }
        // Delegates essentially forcibly match some string, so we can turn them into a token
        RegexExpr::Delegate { inner, casei, .. } => Some(ExprNode::new_prev(Expr::Token(if *casei {
            Token::new_case(inner, true)
        } else {
            Token::new(inner)
        }), previous, parent)),
        // note that since we convert backrefs to tokens, the complexity of a vulnerability
        // may underestimate the actual complexity, though this will not cause
        // false negatives
        RegexExpr::Backref(_) => unimplemented!("Backrefs are not supported yet."),
        RegexExpr::AtomicGroup(e) => {
            container(previous, parent, group_increment, config, e, |tree: Option<ExprNode>| {
                Expr::AtomicGroup(
                    Box::new(tree.unwrap())
                )
            })
        }
        RegexExpr::KeepOut => unimplemented!("Keep out not supported."),
        RegexExpr::ContinueFromPreviousMatchEnd => {
            unimplemented!("Continue from previous match end not supported.")
        }
        RegexExpr::BackrefExistsCondition(_) => unimplemented!("Backref conditions not supported"),
        RegexExpr::Conditional {
            condition,
            true_branch,
            false_branch,
        } => {
            let mut condition_parent = ExprNode::parented_dummy(parent.clone(), previous.clone());

            let true_branch = to_nested_expr(true_branch, config, group_increment, Some(condition_parent.clone()), Some(condition_parent.clone()));
            let false_branch = to_nested_expr(false_branch, config, group_increment, Some(condition_parent.clone()), Some(condition_parent.clone()));
            if let (Some(true_branch), Some(false_branch)) = (true_branch, false_branch) {
                let condition: Option<ExprConditional> = match condition.as_ref() {
                    &RegexExpr::BackrefExistsCondition(number) => {
                        Some(ExprConditional::BackrefExistsCondition(number))
                    }
                    expr => to_nested_expr(expr, config, group_increment, parent, previous)
                        .map(|x| ExprConditional::Condition(Box::new(x))),
                };

                let condition = condition.map(|condition| Expr::Conditional {
                    condition,
                    true_branch: Box::new(true_branch),
                    false_branch: Box::new(false_branch),
                });

                if condition.is_none() {
                    return None;
                }

                condition_parent.current = condition.unwrap();

                Some(condition_parent)
            } else {
                return None;
            }
        }
    }
}
