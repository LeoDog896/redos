use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::alphanumeric1,
    multi::many1,
    sequence::{delimited, pair},
    IResult, Parser,
};

/// Parses regex character literals, returning a string that can match with it
fn literal(i: &str) -> IResult<&str, String> {
    let (i, hit) = alt((
        // escape characters
        tag("\\n").map(|_| "\n".to_string()),
        tag("\\t").map(|_| "\t".to_string()),
        tag("\\r").map(|_| "\r".to_string()),
        // character classes
        tag("\\d").map(|_| "0".to_string()),
        tag("\\D").map(|_| "D".to_string()),
        tag("\\w").map(|_| "w".to_string()),
        tag("\\W").map(|_| "0".to_string()),
        tag("\\s").map(|_| " ".to_string()),
        tag("\\S").map(|_| "S".to_string()),
        alphanumeric1.map(|s: &str| s.to_string()),
    ))(i)?;

    Ok((i, hit))
}

/// Parses regex character literals, laxed since they're inside a character class
fn character_class_literal(i: &str) -> IResult<&str, String> {
    let (i, hit) = alt((literal, alt((tag("$"), tag("^"))).map(|_| "".to_string())))(i)?;

    Ok((i, hit))
}

/// Parses a character class, returning a string that can match with it
fn character_class(i: &str) -> IResult<&str, String> {
    // TODO: support ranges
    let (i, hit) = delimited(
        tag("["),
        alt((
            // TODO: properly find attack string for negated character classes
            pair(tag("^"), many1(literal)).map(|_| "".to_string()),
            many1(character_class_literal).map(|s| s.first().unwrap().to_string()),
        )),
        tag("]"),
    )(i)?;

    Ok((i, hit))
}
