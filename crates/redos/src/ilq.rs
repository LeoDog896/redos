use crate::ir::{Expr, ExprNode, IrAssertion};

/// Represents the result of an ILQ scan
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IlqReturn {
    /// Whether the regex contains an ilq vulnerability
    pub is_present: bool,
}

impl IlqReturn {
    /// Creates a new IlqReturn
    fn new(is_present: bool) -> Self {
        Self { is_present }
    }
}

/// Scans a regex tree for an initial large quantifier 'vulnerability'.
/// Assumes `expr` is the root expression of the tree.
///
/// The regex must match the pattern (where t is arbitrary matchable tokens):
/// t*t+t+
pub fn scan_ilq(expr: &ExprNode) -> IlqReturn {
    match &expr.current {
        // if we hit anything that isn't a Vec<Expr>, we're done
        Expr::Token(_) => IlqReturn::new(false),
        Expr::Assertion(_) => IlqReturn::new(false),

        // hit an alternation? scan_ilq on the children; we can simply pretend
        // as if they're also roots of their own trees.
        // lets find the first child that is an ilq vulnerability
        Expr::Alt(list) => list.iter().fold(IlqReturn::new(false), |acc, e| {
            if acc.is_present {
                acc
            } else {
                scan_ilq(&e)
            }
        }),

        // hit an optional token? we're done! an optional token
        // in the root immediately indicates that it matches an empty string,
        // and thus will finish in a minimal amount of time
        Expr::Optional(_) => IlqReturn::new(false),

        // if we hit some combinations of tokens, lets scan the children.
        // since this is the root node, the false branch is the only one that matters
        Expr::Conditional { false_branch, .. } => scan_ilq(&false_branch),
        Expr::Concat(list) => {
            // We care strongly about Concat nodes, as they represent a sequence of tokens.
            // Lets loop through the list of tokens and scan them.
            // If any of them are a required token with no repetition, we can skip them.

            // Once we hit a required token with repetition, we need to finally make sure there exists
            // a required token.

            scan_ilq_concat(&list)
        }
        Expr::Group(e, _) => scan_ilq(&e),

        // a repeating token? interesting.. we'll need to scan the child
        // luckily, we can just pretend as if the child is the root of its own tree
        Expr::Repeat(e) => scan_ilq(&e),

        // TODO: proper support for lookarounds
        Expr::LookAround(e, _) => scan_ilq(&e),

        // TODO: proper support for atomic groups
        Expr::AtomicGroup(e) => scan_ilq(&e),
    }
}

enum ConcatResults {
    FoundRepeatToken,
    HitRequiredToken,
    Continue,
}

fn scan_ilq_concat(exprs: &Vec<ExprNode>) -> IlqReturn {
    // first, lets try to hit a repeat token
    for expr in exprs {
        let result: ConcatResults = match expr {
            Expr::Token => ConcatResults::HitRequiredToken,
            Expr::Assertion(assertion) => match assertion {
                IrAssertion::Start => ConcatResults::HitRequiredToken,
                IrAssertion::End => ConcatResults::HitRequiredToken,
                IrAssertion::WordBoundary => ConcatResults::HitRequiredToken,
                // since this is 'not' a word boundary,
                // it isn't a required token, so we can continue with our search
                IrAssertion::NotWordBoundary => ConcatResults::Continue,
                IrAssertion::LeftWordBoundary => ConcatResults::HitRequiredToken,
                IrAssertion::RightWordBoundary => ConcatResults::HitRequiredToken,
            },
            Expr::Alt(list) => (),
            Expr::Optional(_) => (),
            Expr::Conditional { false_branch, .. } => (),

            Expr::Concat(list) => (),

            // We encountered one!
            Expr::Repeat(e) => (),

            Expr::Group(e, _) => (),
            Expr::LookAround(e, _) => (),
            Expr::AtomicGroup(e) => (),
        };
    }

    // TODO: implement this
    IlqReturn::new(false)
}
