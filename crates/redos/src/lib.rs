pub mod parse;
pub mod vulnerability;

use vulnerability::Vulnerability;

/// Returns the list of vulnerabilities in a regex
pub fn vulnerabilities(regex: &str) -> Vec<Vulnerability> {
    // search for vulnerable quantifiers - +, *, `{`
    if !regex.contains('+') && !regex.contains('*') && !regex.contains('{') {
        return vec![];
    }

    // TODO: this is a fake placeholder
    vec![Vulnerability::ExponentialOverlappingDisjunction]
}
