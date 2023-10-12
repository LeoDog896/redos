use crate::vulnerability::Vulnerability;
use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    character::complete::one_of,
    combinator::recognize,
    multi::{many0, separated_list0},
    sequence::{delimited, pair},
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
        // general escape character
        pair(tag("\\"), take(1 as usize)).map(|(_, s): (&str, &str)| s.split_at(1).1),
        tag("\\\\").map(|_| "\\"),
        // character classes
        tag("\\d").map(|_| "0"),
        tag("\\D").map(|_| "D"),
        tag("\\w").map(|_| "w"),
        tag("\\W").map(|_| "0"),
        tag("\\s").map(|_| " "),
        tag("\\S").map(|_| "S"),
        // TODO: unicode support for \uXXXX and \x{XXXX}
        // TODO: unicode categories
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

/// Parses a character class, returning a string that can match with it
fn character_class(i: &str) -> IResult<&str, &str> {
    delimited(
        tag("["),
        alt((
            pair(tag("^"), many0(character_class_literal)).map(|(_, negation)| {
                if negation.len() == 0 {
                    "." // [^] is the same as . in regex
                } else {
                    unreachable!("TODO: support negation & ranges")
                }
            }),
            // we can just get the first char here - ranges don't truly matter
            // TODO: [] sets don't match with *anything*
            many0(character_class_literal)
                .map(|s| *s.first().expect("No support for empty ranges yet")),
        )),
        tag("]"),
    )(i)
}

/// Parses a group, returning an attack string & potential vulnerabilities.
fn group(i: &str) -> IResult<&str, Vec<Vec<&str>>> {
    // TODO: support group types
    delimited(tag("("), regex, tag(")"))(i)
}

/// Parses a "piece" of a regex, i.e. a single group or char, and returns an attack string
fn piece(i: &str) -> IResult<&str, &str> {
    // TODO: group support
    // TODO: actual detection
    alt((character_class, regex_literal))(i)
}

/// Parses every alternation of a regex, returning a Vec of Vec<attack strings>.
/// Each element in the top-level Vec is a different alternation.
fn regex(i: &str) -> IResult<&str, Vec<Vec<&str>>> {
    // TODO: separate with | char
    // TODO: proper parsing support for empty alternations
    separated_list0(tag("|"), many0(piece))(i)
}

#[cfg(test)]
mod tests {
    fn safe() {}
}
