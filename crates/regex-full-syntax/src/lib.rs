use std::fmt::Display;
use std::str::FromStr;

use pest::Parser;
use pest::iterators::Pair;
use pest::error::Error;
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "regex.pest"]
struct RegexParser;

#[derive(Debug)]
enum Char {
    Literal(String),
    Escape(char),
    Any,
    Range(char, char),
    Unicode(char),
    UnicodeRange(char, char),
}

impl Display for Char {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Char::Literal(c) => write!(f, "{}", c)?,
            Char::Escape(c) => write!(f, "\\{}", c)?,
            Char::Any => write!(f, ".")?,
            Char::Range(a, b) => write!(f, "{}-{}", a, b)?,
            Char::Unicode(c) => write!(f, "\\u{{{}}}", c)?,
            Char::UnicodeRange(a, b) => write!(f, "\\u{{{}}}-\\u{{{}}}", a, b)?,
        }

        Ok(())
    }
}

#[derive(Debug)]
struct QuantifiableChar {
    char: Char,
    quantifier: Option<Quantifier>,
}

impl Display for QuantifiableChar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.char, self.quantifier)
    }
}

#[derive(Debug)]
enum Quantifier {
    ZeroOrOne,
    ZeroOrMore,
    OneOrMore,
    UpperBoundedRange(Option<usize>, usize),
    LowerBoundedRange(usize, Option<usize>),
}

impl Display for Quantifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Quantifier::ZeroOrOne => write!(f, "?")?,
            Quantifier::ZeroOrMore => write!(f, "*")?,
            Quantifier::OneOrMore => write!(f, "+")?,
            Quantifier::UpperBoundedRange(min, max) => {
                if let Some(min) = min {
                    write!(f, "{{{},", min)?;
                } else {
                    write!(f, "{{,")?;
                }

                write!(f, "{}", max)?;

                write!(f, "}}")?;
            },
            Quantifier::LowerBoundedRange(min, max) => {
                write!(f, "{{{},", min)?;

                if let Some(max) = max {
                    write!(f, "{}", max)?;
                }

                write!(f, "}}")?;
            },
        }

        Ok(())
    }
}

#[derive(Debug)]
enum GroupType {
    PositiveLookahead,
    NegativeLookahead,
    PositiveLookbehind,
    NegativeLookbehind,
    NonCapturing,
    Capturing,
}

impl Display for GroupType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GroupType::PositiveLookahead => write!(f, "?=")?,
            GroupType::NegativeLookahead => write!(f, "?!")?,
            GroupType::PositiveLookbehind => write!(f, "?<=")?,
            GroupType::NegativeLookbehind => write!(f, "?<!")?,
            GroupType::NonCapturing => write!(f, "?:")?,
            GroupType::Capturing => (),
        }

        Ok(())
    }
}

impl FromStr for GroupType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "?=" => Ok(GroupType::PositiveLookahead),
            "?!" => Ok(GroupType::NegativeLookahead),
            "?<=" => Ok(GroupType::PositiveLookbehind),
            "?<!" => Ok(GroupType::NegativeLookbehind),
            "?:" => Ok(GroupType::NonCapturing),
            _ => Err(())
        }
    }
}

#[derive(Debug)]
struct Group {
    group_type: GroupType,
    regex: Regex,
    quantifier: Option<Quantifier>,
}

#[derive(Debug)]
enum Expression {
    String(Vec<QuantifiableChar>),
    CharacterClass(Vec<Char>),
    Group(Group),
}

/// A regular expression
/// is an alternation of sequences of expressions
#[derive(Debug)]
pub struct Regex(Vec<Vec<Expression>>);

impl Display for Regex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut first = true;

        for sequence in &self.0 {
            if !first {
                write!(f, "|")?;
            }

            first = false;

            for expression in sequence {
                match expression {
                    Expression::String(chars) => {
                        for c in chars {
                            write!(f, "{}", c)?;
                        }
                    },
                    Expression::CharacterClass(chars) => {
                        write!(f, "[")?;

                        for c in chars {
                            write!(f, "{}", c)?;
                        }

                        write!(f, "]")?;
                    },
                    Expression::Group(group) => {
                        write!(f, "({}{})", group.group_type, group.regex)?;
                    },
                }
            }
        }

        Ok(())
    }
}

pub fn parse(input: &str) -> Result<Regex, Error<Rule>> {
    let regex_tokens = RegexParser::parse(Rule::regex, input)?.next().unwrap();

    for expression in regex_tokens.into_inner() {
        match expression.as_rule() {
            Rule::alternation => {
                return Ok(parse_alternation(expression));
            },
            Rule::EOI => (),
            _ => unreachable!()
        }
    }

    unreachable!("The regex parser should always return an alternation")
}

fn parse_alternation(alternation: Pair<Rule>) -> Regex {
    let mut regex = Regex(Vec::new());

    for expression in alternation.into_inner() {
        let mut sequence = Vec::<Expression>::new();
        for sub_expression in expression.into_inner() {
            sequence.push(parse_expression(sub_expression));
        }
        regex.0.push(sequence);
    }

    regex
}

fn parse_character(expr: Pair<Rule>) -> Char {
    assert!(expr.as_rule() == Rule::character);

    Char::Literal(expr.as_str().to_string())
}

fn parse_expression(expr: Pair<Rule>) -> Expression {
    match expr.as_rule() {
        Rule::characters => {
            let mut chars = Vec::<QuantifiableChar>::new();

            for c in expr.into_inner() {
                match c.as_rule() {
                    Rule::character => {
                        chars.push(QuantifiableChar {
                            char: parse_character(c),
                            quantifier: None
                        });
                    },
                    Rule::EOI => (),
                    _ => unreachable!()
                }
            }

            Expression::String(chars)
        },
        Rule::group => {
            let mut group_type = GroupType::Capturing;
            let mut regex = Regex(Vec::new());

            for g in expr.into_inner() {
                match g.as_rule() {
                    Rule::group_modifier => {
                        group_type = GroupType::from_str(g.as_str()).unwrap();
                    },
                    Rule::alternation => {
                        regex = parse_alternation(g);
                    },
                    Rule::EOI => (),
                    _ => unreachable!()
                }
            }

            Expression::Group(Group {
                group_type,
                regex,
                quantifier: None,
            })
        },
        _ => unreachable!()
    }
}