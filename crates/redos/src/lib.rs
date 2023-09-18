use regex_full_syntax::{parse, Expression, Regex};

/// Checks if the regex is "complex" (or has any quantifiers)
pub fn is_simple_regex(regex: Regex) -> bool {
    for alternation in regex.0 {
        for expression in alternation {
            match expression {
                Expression::Group(group) => {
                    if group.quantifier.is_none() {
                        continue;
                    }

                    return is_simple_regex(group.regex);
                }
                Expression::String(str) => {
                    for char in str {
                        if char.quantifier.is_some() {
                            return false;
                        }
                    }
                }
                Expression::CharacterClass(_) => (),
            }
        }
    }

    true
}

/// Returns true if not vulnerable, false otherwise
pub fn safe(regex: &str) -> bool {
    let regex = parse(regex).unwrap();
    for alternation in regex.0 {
        for expression in alternation {
            // looking for groups - if there's no groups, we can assume its safe
            if let Expression::Group(group) = expression {
                // and the group must have a quantifier
                if group.quantifier.is_none() {
                    continue;
                }

                return is_simple_regex(group.regex);
            }
        }
    }

    true
}
