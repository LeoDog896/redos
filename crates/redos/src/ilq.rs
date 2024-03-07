use crate::ir::Expr;

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

/// Scans a regex tree for an ilq 'vulnerability'. Assumes `expr` is the root expression of the tree.
pub fn scan_ilq(expr: &Expr) -> IlqReturn {
    match expr {
        // if we hit anything that isn't a Vec<Expr>, we're done
        Expr::Token => IlqReturn::new(false),
        Expr::Assertion(_) => IlqReturn::new(false),

        // hit an alternation? scan_ilq on the children; we can simply pretend
        // as if they're also roots of their own trees.
        // lets find the first child that is an ilq vulnerability
        Expr::Alt(list) => list.iter().fold(IlqReturn::new(false), |acc, e| {
            if acc.is_present {
                acc
            } else {
                scan_ilq(e)
            }
        }),

        // hit an optional token? we're done! an optional token
        // in the root immediately indicates that it matches an empty string,
        // and thus will finish in a minimal amount of time
        Expr::Optional(_) => IlqReturn::new(false),

        // if we hit some combinations of tokens, lets scan the children
        Expr::Conditional { false_branch, .. } => IlqReturn::new(scan_ilq_nested(false_branch)),
        Expr::Concat(list) => IlqReturn::new(list.iter().any(scan_ilq_nested)),
        Expr::Group(e, _) => IlqReturn::new(scan_ilq_nested(e)),

        // a repeating token? interesting.. we'll need to scan the child
        // luckily, we can just pretend as if the child is the root of its own tree
        Expr::Repeat(e) => scan_ilq(e),

        Expr::LookAround(e, _) => scan_ilq(e),

        // TODO: atomic groups and lookarounds
        _ => IlqReturn::new(true),
    }
}

/// Scans a regex tree for an ilq 'vulnerability'
fn scan_ilq_nested(expr: &Expr) -> bool {
    match expr {
        // if we hit a non-optional token, we're done
        Expr::Token => false,

        // TODO: finish?
        _ => true,
    }
}
