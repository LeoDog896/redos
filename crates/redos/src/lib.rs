mod parse;

#[derive(Debug, PartialEq, Eq)]
pub enum Vulnerability {
    ExponentialOverlappingDisjunction,
    OverlappingAdjacency(Complexity),
    NestedQuantifier,
    InitialQuantifier,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Complexity {
    Exponential,
    Polynomial,
}

/// Returns the list of vulnerabilities in a regex
pub fn vulnerabilities(regex: &str) -> Vec<Vulnerability> {
    // search for vulnerable quantifiers - +, *, `{`
    if !regex.contains("+") && !regex.contains("*") && !regex.contains("{") {
        return vec![];
    }

    // TODO: this is a fake placeholder
    vec![Vulnerability::ExponentialOverlappingDisjunction]
}
