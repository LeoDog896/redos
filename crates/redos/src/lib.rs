use regex_full_syntax::{parse, Expression};

/// Returns true if not vulnerable, false otherwise
pub fn safe(regex: &str) -> bool {
    let regex = parse(regex).unwrap();
    for alternation in regex.0 {
        for expression in alternation {
            if let Expression::Group(group) = expression {
                if group.quantifier.is_some() {
                    return false;
                }
            }
        }
    }

    true
}
