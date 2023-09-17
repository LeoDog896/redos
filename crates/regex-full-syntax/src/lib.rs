use std::fmt::Display;
use std::str::FromStr;

use pest::error::Error;
use pest::iterators::Pair;
use pest::Parser;
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
    character: Char,
    quantifier: Option<Quantifier>,
}

impl Display for QuantifiableChar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(quantifier) = &self.quantifier {
            write!(f, "{}{}", self.character, quantifier)
        } else {
            write!(f, "{}", self.character)
        }
    }
}

#[derive(Debug)]
struct Quantifier(usize, Option<usize>);

impl Display for Quantifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(max) = self.1 {
            if self.0 == max {
                write!(f, "{{{}}}", self.0)?;
            } else {
                write!(f, "{{{},{}}}", self.0, max)?;
            }
        } else {
            write!(f, "{{{}}}", self.0)?;
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
            _ => Err(()),
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
                    }
                    Expression::CharacterClass(chars) => {
                        write!(f, "[")?;

                        for c in chars {
                            write!(f, "{}", c)?;
                        }

                        write!(f, "]")?;
                    }
                    Expression::Group(group) => {
                        write!(f, "({}{})", group.group_type, group.regex)?;
                    }
                }
            }
        }

        Ok(())
    }
}

pub fn ast(input: &str) -> Result<Pair<Rule>, Error<Rule>> {
    Ok(RegexParser::parse(Rule::regex, input)?.next().unwrap())
}

pub fn parse(input: &str) -> Result<Regex, Error<Rule>> {
    let regex_tokens = RegexParser::parse(Rule::regex, input)?.next().unwrap();

    for expression in regex_tokens.into_inner() {
        match expression.as_rule() {
            Rule::alternation => {
                return Ok(parse_alternation(expression));
            }
            Rule::EOI => (),
            _ => unreachable!(),
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

fn parse_quantifier(quantifier: Pair<Rule>) -> Quantifier {
    match quantifier.as_rule() {
        Rule::star => Quantifier(0, None),
        Rule::plus => Quantifier(1, None),
        Rule::lazy => Quantifier(0, Some(1)),
        Rule::count => {
            let mut bounds = quantifier.into_inner();

            let min = bounds.next().unwrap().as_str().parse::<usize>().unwrap();
            let max = bounds.next().unwrap().as_str().parse::<usize>().unwrap();

            Quantifier(min, Some(max))
        }

        _ => unreachable!(),
    }
}

fn parse_char(character: Pair<Rule>) -> Char {
    let c = character.as_str();

    if c.len() == 1 {
        Char::Literal(c.to_string())
    } else {
        unimplemented!("Other characters")
    }
}

fn parse_expression(expr: Pair<Rule>) -> Expression {
    match expr.as_rule() {
        Rule::characters => {
            let mut chars = Vec::<QuantifiableChar>::new();
            let mut quantifier: Option<Quantifier> = None;
            let mut current_char: Option<Char> = None;

            for c in expr.into_inner() {
                match c.as_rule() {
                    Rule::all_char => {
                        if let Some(character) = current_char {
                            chars.push(QuantifiableChar {
                                character,
                                quantifier,
                            });
                            quantifier = None;
                        }
                        current_char = Some(parse_char(c));
                    }
                    Rule::quantifier => {
                        quantifier = Some(parse_quantifier(c));
                    }
                    Rule::EOI => (),
                    _ => unreachable!(),
                }
            }

            if let Some(character) = current_char {
                chars.push(QuantifiableChar {
                    character,
                    quantifier,
                });
            }

            Expression::String(chars)
        }
        Rule::group => {
            let mut group_type = GroupType::Capturing;
            let mut regex = Regex(Vec::new());

            for g in expr.into_inner() {
                match g.as_rule() {
                    Rule::group_modifier => {
                        group_type = GroupType::from_str(g.as_str()).unwrap();
                    }
                    Rule::alternation => {
                        regex = parse_alternation(g);
                    }
                    Rule::EOI => (),
                    _ => unreachable!(),
                }
            }

            Expression::Group(Group {
                group_type,
                regex,
                quantifier: None,
            })
        }
        _ => unreachable!(),
    }
}
