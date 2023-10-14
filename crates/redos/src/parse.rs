//! Regex parsing.
//! Should attempt to comply with as many generic regex rules as possible.
//! Links:
//!     - <https://docs.python.org/3/library/re.html#regular-expression-syntax>

use std::borrow::Cow;

use crate::vulnerability::Vulnerability;
use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    character::complete::{digit1, one_of},
    combinator::{map, opt, recognize, value},
    multi::{many0, many_m_n, separated_list0},
    sequence::{delimited, pair, preceded, separated_pair},
    IResult, Parser,
};

/// Utility method to transform an output into a Cow
fn cow<'a, B, I, O, E, F>(mut parser: F) -> impl FnMut(I) -> IResult<I, Cow<'a, B>, E>
where
    F: Parser<I, O, E>,
    B: ToOwned + ?Sized + 'a,
    O: Clone + Into<Cow<'a, B>>,
{
    move |input: I| {
        let (input, o1) = parser.parse(input)?;
        Ok((input, o1.into()))
    }
}

/// Parses regex character literals, returning a string that can match with it
fn literal(i: &str) -> IResult<&str, Cow<str>> {
    alt((
        // Unicode support: Since unicode transforms the input, we need to own it
        // TODO: unicode support for \x{XXXX}
        // TODO: unicode categories
        cow(preceded(
            tag("\\u"),
            many_m_n(4, 4, recognize(one_of("0123456789abcdefABCDEF"))),
        )
        .map(|hex| {
            std::char::from_u32(u32::from_str_radix(&hex.join("").to_lowercase(), 16).unwrap())
                .unwrap()
                .to_string()
        })),
        cow(alt((
            // escape characters
            value("\n", tag("\\n")),
            value("\t", tag("\\t")),
            value("\r", tag("\\r")),
            value("\x0B", tag("\\v")),
            value("\x0C", tag("\\f")),
            value("\0", tag("\\0")),
            value("\0", tag("\\x")),
            // general escape character
            preceded(tag("\\"), take(1_usize)),
            value("\\\\", tag("\\")),
            // character classes
            value("0", tag("\\d")),
            value("D", tag("\\D")),
            value("w", tag("\\w")),
            value("0", tag("\\W")),
            value(" ", tag("\\s")),
            value("S", tag("\\S")),
            // other symbols: we can just put "." as a dot since it matches everything
            // (refactor)TODO: better alphanumeric support (alphanumberic1 exists but it matches multiple)
            recognize(one_of(
                "!@#%&_~`.<>/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
            )),
        ))),
    ))(i)
}

/// Parse regex character literals outside of a character class
fn regex_literal(i: &str) -> IResult<&str, Cow<str>> {
    alt((literal, cow(recognize(one_of("-")))))(i)
}

/// Parses regex character literals, laxed since they're inside a character class
fn character_class_literal(i: &str) -> IResult<&str, Cow<str>> {
    alt((
        literal,
        cow(recognize(one_of("$^|.?*{}[()"))),
        // we dont need to check for \\] since we do that in literal already
    ))(i)
}

/// Parses a range to be used inside a character class
fn range(i: &str) -> IResult<&str, (Cow<str>, Cow<str>)> {
    separated_pair(character_class_literal, tag("-"), character_class_literal)(i)
}

/// Parses a character class, returning a string that can match with it.
/// We must own the returned String here, as this function sometimes doesn't
/// produce a result owned by the input string.
fn character_class(i: &str) -> IResult<&str, Option<Cow<str>>> {
    delimited(
        tag("["),
        alt((
            preceded(
                tag("^"),
                // we turn the literal into a subrange
                many0(alt((
                    range,
                    character_class_literal.map(|x| (x.clone(), x)),
                ))),
            )
            .map(|negation| -> Option<Cow<str>> {
                if negation.is_empty() {
                    Some(".".into()) // [^] is the same as . in regex
                } else {
                    // turn the negation vec into a hashmap
                    let mut negation_map = std::collections::HashMap::new();
                    for (start, end) in negation {
                        negation_map.insert(start.to_string(), end.to_string());
                    }

                    // go through every unicode character and check if it's in the negation map, till we find one that isn't
                    let mut i = 0;
                    // only go up to u16::MAX since we don't need to check for unicode characters above that
                    while i <= std::u16::MAX as u32 {
                        let c = std::char::from_u32(i).unwrap();
                        if negation_map.contains_key(&c.to_string()) {
                            i = negation_map[&c.to_string()].chars().next().unwrap() as u32 + 1;
                        } else {
                            return Some(Cow::Owned(c.to_string()));
                        }
                    }

                    None
                }
            }),
            // we can just get the first char here - ranges don't truly matter
            // TODO: [] sets don't match with *anything*
            many0(alt((
                character_class_literal,
                cow(tag("-")),
            )))
            .map(|s| s.first().cloned()),
        )),
        tag("]"),
    )(i)
}

/// A regex quantifier, with a range and a lazy flag
/// Represents {lower, Option<upper>}[?]
#[derive(Debug, PartialEq, Eq)]
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
                value((0, None), tag("*")),
                value((1, None), tag("+")),
                value((0, Some(1)), tag("?")),
                map(
                    delimited(
                        tag("{"),
                        pair(digit1::<&str, _>, opt(pair(tag(","), opt(digit1)))),
                        tag("}"),
                    ),
                    |(lower, opt)| {
                        (
                            lower.parse::<u32>().unwrap(),
                            if let Some((_, opt)) = opt {
                                opt.map(|x| x.parse::<u32>().unwrap())
                            } else {
                                Some(lower.parse::<u32>().unwrap())
                            },
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
fn group(i: &str) -> IResult<&str, Vec<Vec<Option<Cow<str>>>>> {
    // TODO: support group types
    delimited(tag("("), regex, tag(")"))(i)
}

/// Parses a "piece" of a regex, i.e. a single group or char, and returns an attack string
fn piece(i: &str) -> IResult<&str, Option<Cow<str>>> {
    // TODO: group support
    // TODO: actual detection
    // TODO: quantifier support (lazy & non-lazy)
    alt((character_class, regex_literal.map(Some)))(i)
}

/// Parses every alternation of a regex, returning a Vec of Vec<attack strings>.
/// Each element in the top-level Vec is a different alternation.
fn regex(i: &str) -> IResult<&str, Vec<Vec<Option<Cow<str>>>>> {
    // TODO: proper parsing support for cancelled alternations (e.g. a||b)
    separated_list0(tag("|"), many0(piece))(i)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn character_class_hit() {
        assert_eq!(character_class("[ba-cd]"), Ok(("", Some("b".into()))));
        assert_eq!(character_class("[-token]"), Ok(("", Some("-".into()))));
        assert_eq!(character_class("[^a]"), Ok(("", Some("\x00".into()))));
        assert_eq!(character_class("[^\\u0000-\\u0021]"), Ok(("", Some("\x22".into()))));
        assert_eq!(character_class("[^\\u0000-\\u0021\\u0023-\\uFFFF]"), Ok(("", Some("\x22".into()))));
        assert_eq!(character_class("[^\\u0022-\\uFFFF\\u0000-\\u0021]"), Ok(("", None)));
        assert_eq!(character_class("[^\\u0000-\\u0021\\u0022-\\uFFFE]"), Ok(("", Some("\u{FFFF}".into()))));
        // TODO: when we have unicode ranges, test without a null char.
    }

    #[test]
    fn quantifier_hit() {
        assert_eq!(quantifier("*"), Ok(("", Quantifier::range(0, None))));
        assert_eq!(quantifier("+"), Ok(("", Quantifier::range(1, None))));
        assert_eq!(quantifier("?"), Ok(("", Quantifier::range(0, Some(1)))));
        assert_eq!(quantifier("{1}"), Ok(("", Quantifier::range(1, Some(1)))));
        assert_eq!(quantifier("{1,}"), Ok(("", Quantifier::range(1, None))));
        assert_eq!(
            quantifier("{1,24}"),
            Ok(("", Quantifier::range(1, Some(24))))
        );
        assert_eq!(
            quantifier("{1,212}?"),
            Ok(("", Quantifier::lazy(1, Some(212))))
        );
        assert_eq!(quantifier("*?"), Ok(("", Quantifier::lazy(0, None))));
    }
}
