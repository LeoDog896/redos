use crate::vulnerability::Vulnerability;
use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    character::complete::{alphanumeric1, one_of},
    combinator::recognize,
    multi::many1,
    sequence::{delimited, pair},
    IResult, Parser,
};

/// Parses regex character literals, returning a string that can match with it
fn literal(i: &str) -> IResult<&str, &str> {
    let (i, hit) = alt((
        // escape characters
        tag("\\n").map(|_| "\n"),
        tag("\\t").map(|_| "\t"),
        tag("\\r").map(|_| "\r"),
        tag("\\v").map(|_| "\x0B"),
        tag("\\f").map(|_| "\x0C"),
        tag("\\0").map(|_| "\0"),
        tag("\\x").map(|_| "\0"),
        // general escape character
        pair(tag("\\"), take(1 as usize)).map(|(_, s): (&str, &str)| s.split_at(1).0),
        // character classes
        tag("\\d").map(|_| "0"),
        tag("\\D").map(|_| "D"),
        tag("\\w").map(|_| "w"),
        tag("\\W").map(|_| "0"),
        tag("\\s").map(|_| " "),
        tag("\\S").map(|_| "S"),
        // other symbols: we can just put "." as a dot since it matches everything
        recognize(one_of("!@#%&_~`.<>")),
        alphanumeric1,
    ))(i)?;

    Ok((i, hit))
}

/// Parse regex character literals outside of a character class
fn regex_literal(i: &str) -> IResult<&str, &str> {
    let (i, hit) = alt((literal, recognize(one_of("-"))))(i)?;

    Ok((i, hit))
}

/// Parses regex character literals, laxed since they're inside a character class
fn character_class_literal(i: &str) -> IResult<&str, &str> {
    let (i, hit) = alt((
        literal,
        recognize(one_of("$^|.?*{}[()")),
        tag("\\]").map(|_| "]"),
    ))(i)?;

    Ok((i, hit))
}

/// Parses a character class, returning a string that can match with it
fn character_class(i: &str) -> IResult<&str, &str> {
    // TODO: support ranges
    let (i, hit) = delimited(
        tag("["),
        alt((
            // TODO: properly find attack string for negated character classes
            pair(tag("^"), many1(character_class_literal)).map(|_| "TODO:NEGATED"),
            many1(character_class_literal).map(|s| *s.first().unwrap()),
        )),
        tag("]"),
    )(i)?;

    Ok((i, hit))
}

/// Parses a "piece" of a regex, i.e. a single group or char, and returns an attack string
fn piece(i: &str) -> IResult<&str, &str> {
    // TODO: group support
    // TODO: actual detection
    alt((character_class, regex_literal))(i)
}
