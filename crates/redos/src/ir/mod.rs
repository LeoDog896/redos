//! Intermediate representation of a regular expression.
//! Used to simplify the AST and make it easier to work with.

mod token;

use token::Token;

use std::{
    num::NonZeroUsize,
    rc::{Rc, Weak},
};

use fancy_regex::{Assertion, Expr as RegexExpr, LookAround};

use crate::vulnerability::VulnerabilityConfig;

use self::token::Value;

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

#[derive(Debug, Clone)]
pub enum ExprConditional {
    Condition(StrongLink<ExprNode>),
    BackrefExistsCondition(usize),
}

/// A reference to another node that doesn't force it to be always held
type WeakLink<T> = Weak<T>;

/// A reference to another node that forces it to be dropped and held.
type StrongLink<T> = Rc<T>;

#[derive(Debug, Clone)]
pub struct ExprNode {
    pub current: Expr,
    pub previous: Option<WeakLink<ExprNode>>,
    pub next: Option<WeakLink<ExprNode>>,
    pub parent: Option<WeakLink<ExprNode>>,
}

impl ExprNode {
    /// Helper function that creates a new node for the IR generation
    fn new_prev(
        current: Expr,
        previous: Option<WeakLink<ExprNode>>,
        parent: Option<WeakLink<ExprNode>>,
    ) -> ExprNode {
        ExprNode {
            current,
            previous,
            next: None,
            parent,
        }
    }

    /// Helper function that creates a new node for the IR generation,
    /// allowing consuming itself to reparent its child expressions.
    fn new_prev_consume_optional<F>(
        current: F,
        previous: Option<WeakLink<ExprNode>>,
        parent: Option<WeakLink<ExprNode>>,
    ) -> Option<ExprNode>
    where
        F: FnOnce(WeakLink<ExprNode>) -> Option<Expr>,
    {
        // Here, we don't care about current; we are going to replace it
        let mut node = ExprNode::new_prev(Expr::Concat(vec![]), previous, parent);

        let child = current(Rc::downgrade(&Rc::new(node.clone())));

        if child.is_none() {
            return None;
        }

        node.current = child.unwrap();

        Some(node)
    }

    /// Checks if this node is an ancestor of another node.
    pub fn is_ancestor_of(&self, other: &ExprNode) -> bool {
        let mut current = other.parent.clone();

        while let Some(parent) = current {
            if let Some(parent) = parent.upgrade() {
                if Rc::ptr_eq(&parent, &Rc::new(self.clone())) {
                    return true;
                }

                current = parent.parent.clone();
            } else {
                break;
            }
        }

        false
    }

    /// Helper function that produces a dummy value
    fn dummy() -> ExprNode {
        ExprNode {
            current: Expr::Token(Token {
                yes: vec![],
                no: vec![],
                ignore_case: false,
            }),
            previous: None,
            next: None,
            parent: None,
        }
    }
}

fn container<F>(
    previous: Option<WeakLink<ExprNode>>,
    parent: Option<WeakLink<ExprNode>>,
    group_increment: NonZeroUsize,
    config: &VulnerabilityConfig,
    expr: &RegexExpr,
    gen: F,
) -> Option<ExprNode>
where
    F: FnOnce(Option<ExprNode>) -> Expr,
{
    let mut node = ExprNode::new_prev(
        Expr::Group(Rc::new(ExprNode::dummy()), group_increment.into()),
        previous,
        parent,
    );

    let rc = Rc::new(node.clone());

    let nest = to_nested_expr(
        expr,
        config,
        group_increment
            .checked_add(1)
            .expect("group increment overflow"),
        Some(Rc::downgrade(&rc)),
        Some(Rc::downgrade(&rc)),
    );

    if nest.is_none() {
        return None;
    }

    node.current = gen(nest);

    Some(node)
}
#[derive(Debug, Clone)]
pub enum Expr {
    /// Some token, whether its a character class, any character, etc.
    Token(Token),
    /// An assertion
    Assertion(IrAssertion),
    /// Concatenation of multiple expressions, must match in order, e.g. `a.` is a concatenation of
    /// the literal `a` and `.` for any character
    Concat(Vec<StrongLink<ExprNode>>),
    /// Alternative of multiple expressions, one of them must match, e.g. `a|b` is an alternative
    /// where either the literal `a` or `b` must match
    Alt(Vec<StrongLink<ExprNode>>),
    /// Capturing group of expression, e.g. `(a.)` matches `a` and any character and "captures"
    /// (remembers) the match
    ///
    /// The usize is the number of the capturing group, starting from 1
    Group(StrongLink<ExprNode>, usize),
    /// Look-around (e.g. positive/negative look-ahead or look-behind) with an expression, e.g.
    /// `(?=a)` means the next character must be `a` (but the match is not consumed)
    LookAround(StrongLink<ExprNode>, LookAround),
    /// Some large repeat of an expression.
    // Implementation Note: Greedy does not matter as if it doesn't match (in the case of ReDoS abuse),
    // greedy will not affect its matching because of the terminal token.
    Repeat(StrongLink<ExprNode>),
    /// Optional expression, e.g. `a?` means `a` is optional
    Optional(StrongLink<ExprNode>),
    /// Atomic non-capturing group, e.g. `(?>ab|a)` in text that contains `ab` will match `ab` and
    /// never backtrack and try `a`, even if matching fails after the atomic group.
    AtomicGroup(StrongLink<ExprNode>),
    /// If/Then/Else Condition. If there is no Then/Else, these will just be empty expressions.
    Conditional {
        /// The conditional expression to evaluate
        condition: ExprConditional,
        /// What to execute if the condition is true
        true_branch: StrongLink<ExprNode>,
        /// What to execute if the condition is false
        false_branch: StrongLink<ExprNode>,
    },
}

pub fn to_expr(expr: &RegexExpr, config: &VulnerabilityConfig) -> Option<ExprNode> {
    let expr = to_nested_expr(expr, config, nonzero_lit::usize!(1), None, None);

    if expr.is_none() {
        return None;
    }

    let expr = expr.unwrap();

    // set all `next` pointers
    // walk_unordered(expr.clone(), |e| {
    //     if let Some(prev) = e.previous.clone() {
    //         if let Some(prev) = prev.upgrade() {
    //             prev.next = Some(Rc::downgrade(&Rc::new(e.clone())));
    //         }
    //     }
    // });

    Some(expr)
}

/// Walks through every node with no guaranteed order.
fn walk_unordered<F>(expr: &Rc<ExprNode>, mut f: F)
where
    F: FnMut(Rc<ExprNode>),
{
    f(expr.clone());

    match &expr.current {
        Expr::Concat(list) => {
            for e in list {
                walk_unordered(e, &mut f);
            }
        }
        Expr::Alt(list) => {
            for e in list {
                walk_unordered(e, &mut f);
            }
        }
        Expr::Group(e, _) => {
            walk_unordered(e, &mut f);
        }
        Expr::LookAround(e, _) => {
            walk_unordered(e, &mut f);
        }
        Expr::AtomicGroup(e) => {
            walk_unordered(e, &mut f);
        }
        Expr::Optional(e) => {
            walk_unordered(e, &mut f);
        }
        Expr::Repeat(e) => {
            walk_unordered(e, &mut f);
        }
        Expr::Conditional {
            true_branch,
            false_branch,
            condition,
        } => {
            walk_unordered(true_branch, &mut f);
            walk_unordered(false_branch, &mut f);

            if let ExprConditional::Condition(e) = condition {
                walk_unordered(e, &mut f);
            }
        }
        _ => {}
    }
}

/// Finds the first node of a certain type in the ancestors of an expression,
/// where $expr is the expression to search in and $type is the type of node to search for.
#[macro_export]
macro_rules! find_ancestor_type {
    (
        $expr:expr,
        $type:ident
    ) => {
        'func: {
            let mut current = $expr.clone();

            while let Some(parent) = current.parent.clone() {
                if let Some(parent) = parent.upgrade() {
                    if let Expr::$type(_) = &parent.current {
                        break 'func Some(parent);
                    }

                    current = parent;
                } else {
                    break 'func None;
                }
            }

            false
        }
    };
}

/// Finds the first node of a certain type in an expression,
/// where $expr is the expression to search in and $type is the type of node to search for.
///
/// Optionally, you can specify a few additional parameters:
/// - `$always_ancestor`: The node that must always be an ancestor of the node
/// - `$never_ancestor`: The node that must never be an ancestor of the node
/// - `$never_ancestor_type`: The type of node that must never be an ancestor of the node
/// - `$never_ancestor_type_sandwich`: The type of node that must never be an ancestor of the node,
/// excluding ancestors of those specified in $always_ancestor
#[macro_export]
macro_rules! find_node_type {
    (
        $expr:expr,
        $type:ident
        $(
            ,always_ancestor=$always_ancestor:expr
            $(,never_ancestor_type_sandwich=$never_ancestor_type_sandwich:expr)?
        )?
        $(,never_ancestor=$never_ancestor:expr)?
        $(,never_ancestor_type=$never_ancestor_type:ident)?
    ) => {
        'func: {
            for node in ExprWalker::new($expr.clone()) {
                $(
                    if !node.is_ancestor_of(&$always_ancestor) {
                        continue;
                    }
                )?

                $(
                    if node.is_ancestor_of(&$never_ancestor) {
                        continue;
                    }
                )?

                $(
                    if let Some(found_ancestor) = find_ancestor_type!(node, $never_ancestor_type) {
                        continue;
                    }
                )?

                if let Expr::$type(_) = &node.current {
                    break 'func Some(node);
                }
            }

            None
        }
    }
}

pub struct ExprWalker {
    current: Rc<ExprNode>,
}

impl ExprWalker {
    pub fn new(current: Rc<ExprNode>) -> Self {
        Self { current }
    }

    pub fn walk<F>(&self, f: F)
    where
        F: Fn(Rc<ExprNode>),
    {
        let mut current = self.current.clone();

        while let Some(next) = current.next.clone() {
            if let Some(next) = next.upgrade() {
                f(next.clone());
                current = next;
            } else {
                break;
            }
        }
    }
}

impl Iterator for ExprWalker {
    type Item = Rc<ExprNode>;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.current.next.clone();

        if let Some(next) = next {
            if let Some(next) = next.upgrade() {
                self.current = next.clone();
                return Some(next);
            }
        }

        None
    }
}

fn to_nested_expr(
    expr: &RegexExpr,
    config: &VulnerabilityConfig,
    group_increment: NonZeroUsize,
    parent: Option<WeakLink<ExprNode>>,
    previous: Option<WeakLink<ExprNode>>,
) -> Option<ExprNode> {
    match expr {
        RegexExpr::Empty => None,
        RegexExpr::Any { newline } => Some(ExprNode::new_prev(
            Expr::Token(if *newline {
                Token::new(".")
            } else {
                Token {
                    yes: vec![Value::match_char('.')],
                    no: vec![Value::match_char('\n')],
                    ignore_case: false,
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
        RegexExpr::Concat(list) => ExprNode::new_prev_consume_optional(
            |parent| {
                let no_siblings_list = list
                    .iter()
                    .filter_map(|e| {
                        to_nested_expr(e, config, group_increment, Some(parent.clone()), None)
                    })
                    .map(Rc::new)
                    .collect::<Vec<_>>();

                let nodes = no_siblings_list
                    .iter()
                    .enumerate()
                    .map(|(i, e)| {
                        let previous = if i == 0 {
                            parent.clone()
                        } else {
                            Rc::downgrade(&no_siblings_list[i].clone())
                        };

                        ExprNode {
                            current: e.current.clone(),
                            previous: Some(previous),
                            next: e.next.clone(),
                            parent: e.parent.clone(),
                        }
                    })
                    .map(Rc::new)
                    .collect::<Vec<_>>();

                if nodes.is_empty() {
                    return None;
                }

                Some(Expr::Concat(nodes))
            },
            previous,
            parent,
        ),
        RegexExpr::Alt(list) => ExprNode::new_prev_consume_optional(
            |x| {
                Some(Expr::Alt(
                    list.iter()
                        .filter_map(|e| {
                            to_nested_expr(
                                e,
                                config,
                                group_increment,
                                Some(x.clone()),
                                Some(x.clone()),
                            )
                            .map(Rc::new)
                        })
                        .collect::<Vec<_>>(),
                ))
            },
            previous,
            parent,
        ),
        RegexExpr::Group(e) => container(
            previous,
            parent,
            group_increment,
            config,
            e,
            |tree: Option<ExprNode>| Expr::Group(Rc::new(tree.unwrap()), group_increment.into()),
        ),
        RegexExpr::LookAround(e, la) => container(
            previous,
            parent,
            group_increment,
            config,
            e,
            |tree: Option<ExprNode>| Expr::LookAround(Rc::new(tree.unwrap()), *la),
        ),
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

            ExprNode::new_prev_consume_optional(
                |node| {
                    let repeat_node = if range > config.four_max_quantifier {
                        ExprNode::new_prev_consume_optional(
                            |node| {
                                to_nested_expr(
                                    child.to_owned(),
                                    config,
                                    group_increment,
                                    Some(node.clone()),
                                    Some(node.clone()),
                                )
                                .map(|x| Expr::Repeat(Rc::new(x)))
                            },
                            Some(node.clone()),
                            Some(node.clone()),
                        )
                    } else {
                        to_nested_expr(
                            child,
                            config,
                            group_increment,
                            Some(node.clone()),
                            Some(node.clone()),
                        )
                    };
                    
                    if *lo == 0 {
                        Some(Expr::Optional(Rc::new(repeat_node?)))
                    } else {
                        panic!("Should have been covered by is_complex case");
                    }
                },
                previous,
                parent,
            )
        }
        // Delegates essentially forcibly match some string, so we can turn them into a token
        RegexExpr::Delegate { inner, casei, .. } => Some(ExprNode::new_prev(
            Expr::Token(if *casei {
                Token::new_case(inner, true)
            } else {
                Token::new(inner)
            }),
            previous,
            parent,
        )),
        // note that since we convert backrefs to tokens, the complexity of a vulnerability
        // may underestimate the actual complexity, though this will not cause
        // false negatives
        RegexExpr::Backref(_) => unimplemented!("Backrefs are not supported yet."),
        RegexExpr::AtomicGroup(e) => container(
            previous,
            parent,
            group_increment,
            config,
            e,
            |tree: Option<ExprNode>| Expr::AtomicGroup(Rc::new(tree.unwrap())),
        ),
        RegexExpr::KeepOut => unimplemented!("Keep out not supported."),
        RegexExpr::ContinueFromPreviousMatchEnd => {
            unimplemented!("Continue from previous match end not supported.")
        }
        RegexExpr::BackrefExistsCondition(_) => unimplemented!("Backref conditions not supported"),
        RegexExpr::Conditional {
            condition,
            true_branch,
            false_branch,
        } => ExprNode::new_prev_consume_optional(
            |x| {
                let true_branch = to_nested_expr(
                    true_branch,
                    config,
                    group_increment,
                    Some(x.clone()),
                    Some(x.clone()),
                );
                let false_branch = to_nested_expr(
                    false_branch,
                    config,
                    group_increment,
                    Some(x.clone()),
                    Some(x.clone()),
                );
                if let (Some(true_branch), Some(false_branch)) = (true_branch, false_branch) {
                    let condition: Option<ExprConditional> = match condition.as_ref() {
                        &RegexExpr::BackrefExistsCondition(number) => {
                            Some(ExprConditional::BackrefExistsCondition(number))
                        }
                        expr => to_nested_expr(
                            expr,
                            config,
                            group_increment,
                            Some(x.clone()),
                            Some(x.clone()),
                        )
                        .map(|x| ExprConditional::Condition(Rc::new(x))),
                    };

                    condition.map(|condition| Expr::Conditional {
                        condition,
                        true_branch: Rc::new(true_branch),
                        false_branch: Rc::new(false_branch),
                    })
                } else {
                    None
                }
            },
            previous,
            parent,
        ),
    }
}
