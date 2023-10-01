pub enum Vulnerability {
    ExponentialOverlappingDisjunction,
    OverlappingAdjacency(Complexity),
    NestedQuantifier,
    InitialQuantifier,
}

pub enum Complexity {
    Exponential,
    Polynomial,
}

/// Returns the list of vulnerabilities in a regex
pub fn vulnerabilities(regex: &str) -> Vec<Vulnerability> {
    vec![]
}
