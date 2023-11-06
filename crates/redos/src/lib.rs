pub mod parse;
pub mod vulnerability;

use parse::regex_parse;
use vulnerability::Vulnerability;

/// Returns the list of vulnerabilities in a regex
pub fn vulnerabilities(regex: &str) -> Vec<Vulnerability> {
    // search for vulnerable quantifiers - +, *, `{`
    if !regex.contains('+') && !regex.contains('*') && !regex.contains('{') {
        return vec![];
    }

    let _ = regex_parse(regex).unwrap().1;

    // TODO: this is a fake placeholder
    vec![Vulnerability::ExponentialOverlappingDisjunction]
}
