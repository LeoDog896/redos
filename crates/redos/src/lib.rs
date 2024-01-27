pub mod vulnerability;

use fancy_regex::parse::Parser;
use vulnerability::Vulnerability;

/// Returns the list of vulnerabilities in a regex
pub fn vulnerabilities(regex: &str) -> Vec<Vulnerability> {
    // search for vulnerable quantifiers - +, *, `{`
    if !regex.contains('+') && !regex.contains('*') && !regex.contains('{') {
        return vec![];
    }

    let x = Parser::parse(regex);

    println!("{:?}", x);

    // TODO: this is a fake placeholder
    vec![Vulnerability::ExponentialOverlappingDisjunction]
}
