use std::fmt::Display;

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
enum GroupType {
    PositiveLookahead,
    NegativeLookahead,
    PositiveLookbehind,
    NegativeLookbehind,
    NonCapturing,
    Capturing,
}

#[derive(Debug)]
struct Group {
    group_type: GroupType,
    regex: Regex,
}

#[derive(Debug)]
enum Expression {
    String(Vec<Char>),
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

            let mut first = true;

            for expression in sequence {
                if !first {
                    write!(f, " ")?;
                }

                first = false;

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
                        write!(f, "({})", group.regex)?;
                    },
                }
            }
        }

        Ok(())
    }
}

pub fn parse(input: &str) -> Result<Regex, Error<Rule>> {
    let regex_tokens = RegexParser::parse(Rule::regex, input)?.next().unwrap();
    let mut regex = Regex(Vec::new());

    for expression in regex_tokens.into_inner() {
        match expression.as_rule() {
            Rule::expression => {
                let mut sequence = Vec::<Expression>::new();
                for sub_expression in expression.into_inner() {
                    sequence.push(parse_expression(sub_expression));
                }
                regex.0.push(sequence);
            },
            Rule::EOI => (),
            _ => unreachable!()
        }
    }
    Ok(regex)
}

fn parse_character(expr: Pair<Rule>) -> Char {
    assert!(expr.as_rule() == Rule::character);

    Char::Literal(expr.as_str().to_string())
}

fn parse_expression(expr: Pair<Rule>) -> Expression {
    match expr.as_rule() {
        Rule::characters => {
            let mut chars = Vec::<Char>::new();

            for c in expr.into_inner() {
                match c.as_rule() {
                    Rule::character => {
                        chars.push(parse_character(c));
                    },
                    Rule::EOI => (),
                    _ => unreachable!()
                }
            }

            Expression::String(chars)
        },
        _ => unreachable!()
    }
}