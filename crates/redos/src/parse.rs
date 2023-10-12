//! Regex parsing.
//! Should attempt to comply with as many generic regex rules as possible.
//! Links:
//!     - https://docs.python.org/3/library/re.html#regular-expression-syntax

use crate::vulnerability::Vulnerability;
use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    character::complete::{digit1, one_of},
    combinator::{map, opt, recognize},
    multi::{many0, separated_list0},
    sequence::{delimited, pair, preceded, separated_pair},
    IResult, Parser,
};

/// Parses regex character literals, returning a string that can match with it
fn literal(i: &str) -> IResult<&str, &str> {
    alt((
        // escape characters
        tag("\\n").map(|_| "\n"),
        tag("\\t").map(|_| "\t"),
        tag("\\r").map(|_| "\r"),
        tag("\\v").map(|_| "\x0B"),
        tag("\\f").map(|_| "\x0C"),
        tag("\\0").map(|_| "\0"),
        tag("\\x").map(|_| "\0"),
        // TODO: unicode support for \uXXXX and \x{XXXX}
        // TODO: unicode categories
        // general escape character
        preceded(tag("\\"), take(1 as usize)),
        tag("\\\\").map(|_| "\\"),
        // character classes
        tag("\\d").map(|_| "0"),
        tag("\\D").map(|_| "D"),
        tag("\\w").map(|_| "w"),
        tag("\\W").map(|_| "0"),
        tag("\\s").map(|_| " "),
        tag("\\S").map(|_| "S"),
        // other symbols: we can just put "." as a dot since it matches everything
        // (refactor)TODO: better alphanumeric support (alphanumberic1 exists but it matches multiple)
        recognize(one_of(
            "!@#%&_~`.<>/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
        )),
    ))(i)
}

/// Parse regex character literals outside of a character class
fn regex_literal(i: &str) -> IResult<&str, &str> {
    alt((literal, recognize(one_of("-"))))(i)
}

/// Parses regex character literals, laxed since they're inside a character class
fn character_class_literal(i: &str) -> IResult<&str, &str> {
    alt((
        literal,
        recognize(one_of("$^|.?*{}[()")),
        // we dont need to check for \\] since we do that in literal already
    ))(i)
}

/// Parses a range to be used inside a character class
fn range(i: &str) -> IResult<&str, (&str, &str)> {
    separated_pair(character_class_literal, tag("-"), character_class_literal)(i)
}

/// Parses a character class, returning a string that can match with it.
/// We must own the returned String here, as this function sometimes doesn't
/// produce a result owned by the input string.
fn character_class(i: &str) -> IResult<&str, Option<String>> {
    delimited(
        tag("["),
        alt((
            preceded(
                tag("^"),
                // we turn the literal into a subrange
                many0(alt((range, character_class_literal.map(|x| (x, x))))),
            )
            .map(|negation| {
                if negation.len() == 0 {
                    Some(".".to_string()) // [^] is the same as . in regex
                } else {
                    // turn the negation vec into a hashmap
                    let mut negation_map = std::collections::HashMap::new();
                    for (start, end) in negation {
                        negation_map.insert(start, end);
                    }

                    // go through every unicode character and check if it's in the negation map, till we find one that isn't
                    let mut i = 0;
                    while i < std::u32::MAX {
                        let c = std::char::from_u32(i).unwrap();
                        if !negation_map.contains_key(&c.to_string().as_str()) {
                            return Some(c.to_string());
                        } else {
                            // if we're at the end of the map, we can just return None
                            if i == std::u32::MAX - 1 {
                                return None;
                            }

                            i = negation_map[&c.to_string().as_str()]
                                .chars()
                                .next()
                                .unwrap() as u32;
                        }

                        i += 1;
                    }

                    None
                }
            }),
            // we can just get the first char here - ranges don't truly matter
            // TODO: [] sets don't match with *anything*
            many0(alt((character_class_literal, tag("-"))))
                .map(|s| s.first().map(|x| x.to_string())),
        )),
        tag("]"),
    )(i)
}

struct Quantifier {
    range: (u32, Option<u32>),
    lazy: bool,
}

impl Quantifier {
    fn range(lower: u32, upper: Option<u32>) -> Self {
        Self {
            range: (lower, upper),
            lazy: false,
        }
    }

    fn lazy(lower: u32, upper: Option<u32>) -> Self {
        Self {
            range: (lower, upper),
            lazy: true,
        }
    }
}

/// Parses a regex quantifier, returning its bounds
fn quantifier(i: &str) -> IResult<&str, Quantifier> {
    map(
        pair(
            alt((
                map(tag("*"), |_| (0, None)),
                map(tag("+"), |_| (1, None)),
                map(tag("?"), |_| (0, Some(1))),
                map(
                    pair(digit1::<&str, _>, opt(preceded(tag(","), opt(digit1)))),
                    |(a, b)| {
                        (
                            a.parse::<u32>().unwrap(),
                            b.flatten().map(|x| x.parse::<u32>().unwrap()),
                        )
                    },
                ),
            )),
            opt(tag("?")),
        ),
        |(range, lazy)| {
            if lazy.is_some() {
                Quantifier::lazy(range.0, range.1)
            } else {
                Quantifier::range(range.0, range.1)
            }
        },
    )(i)
}

/// Parses a group, returning an attack string & potential vulnerabilities.
fn group(i: &str) -> IResult<&str, Vec<Vec<Option<String>>>> {
    // TODO: support group types
    delimited(tag("("), regex, tag(")"))(i)
}

/// Parses a "piece" of a regex, i.e. a single group or char, and returns an attack string
fn piece(i: &str) -> IResult<&str, Option<String>> {
    // TODO: group support
    // TODO: actual detection
    // TODO: quantifier support (lazy & non-lazy)
    alt((character_class, regex_literal.map(|x| Some(x.to_string()))))(i)
}

/// Parses every alternation of a regex, returning a Vec of Vec<attack strings>.
/// Each element in the top-level Vec is a different alternation.
fn regex(i: &str) -> IResult<&str, Vec<Vec<Option<String>>>> {
    // TODO: proper parsing support for cancelled alternations (e.g. a||b)
    separated_list0(tag("|"), many0(piece))(i)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn character_class_hit() {
        assert_eq!(character_class("[ba-cd]"), Ok(("", Some("b".to_string()))));
        assert_eq!(character_class("[-token]"), Ok(("", Some("-".to_string()))));
        assert_eq!(character_class("[^a]"), Ok(("", Some("\x00".to_string()))));
        // TODO: when we have unicode ranges, test without a null char.
    }
}
