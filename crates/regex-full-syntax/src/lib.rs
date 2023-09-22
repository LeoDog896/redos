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
pub enum Char {
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
pub struct QuantifiableChar {
    pub character: Char,
    pub quantifier: Option<Quantifier>,
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
pub struct Quantifier {
    pub low: usize,
    pub high: Option<usize>,
    pub lazy: bool,
}

impl Display for Quantifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(max) = self.high {
            if self.low == max {
                write!(f, "{{{}}}", max)?;
            } else {
                write!(f, "{{{},{}}}", self.low, max)?;
            }
        } else {
            write!(f, "{{{},}}", self.low)?;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum GroupType {
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
pub struct Group {
    pub group_type: GroupType,
    pub regex: Regex,
    pub quantifier: Option<Quantifier>,
}

#[derive(Debug)]
pub enum Expression {
    String(Vec<QuantifiableChar>),
    CharacterClass(Vec<Char>),
    Group(Group),
}

/// A regular expression
/// is an alternation of sequences of expressions
#[derive(Debug)]
pub struct Regex(pub Vec<Vec<Expression>>);

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
                        if let Some(quantifier) = &group.quantifier {
                            write!(f, "({}{}){}", group.group_type, group.regex, quantifier)?;
                        } else {
                            write!(f, "({}{})", group.group_type, group.regex)?;
                        }
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
    let regex_tokens = RegexParser::parse(Rule::regex, input).unwrap_or_else(|k| panic!("{}", k)).next().unwrap();

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

fn parse_quantifier(input: Pair<Rule>) -> Quantifier {
    let mut quantifier = Quantifier {
        low: 0,
        high: None,
        lazy: false,
    };

    for token in input.into_inner() {
        match token.as_rule() {
            Rule::star => {
                quantifier.low = 0;
                quantifier.high = None;
            }
            Rule::plus => {
                quantifier.low = 1;
                quantifier.high = None;
            }
            Rule::lazy => {
                quantifier.low = 0;
                quantifier.high = Some(1);
            }
            Rule::count => {
                let mut bounds = token.into_inner();

                let min = bounds.next().unwrap().as_str().parse::<usize>().unwrap();
                let max = bounds.next().and_then(|max| max.as_str().parse::<usize>().ok());

                quantifier.low = min;
                quantifier.high = max;
            }

            _ => unreachable!("Unknown rule: {:?}", token.as_rule()),
        }
    }

    quantifier
}

fn parse_char(character: Pair<Rule>) -> Char {
    let c = character.as_str();

    Char::Literal(c.to_string())
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
            let mut quantifier: Option<Quantifier> = None;

            for g in expr.into_inner() {
                match g.as_rule() {
                    Rule::group_modifier => {
                        group_type = GroupType::from_str(g.as_str()).unwrap();
                    }
                    Rule::alternation => {
                        regex = parse_alternation(g);
                    }
                    Rule::quantifier => {
                        quantifier = Some(parse_quantifier(g));
                    }
                    Rule::EOI => (),
                    _ => unreachable!(),
                }
            }

            Expression::Group(Group {
                group_type,
                regex,
                quantifier,
            })
        }
        Rule::character_group => {
            // TODO: implement char group
            Expression::CharacterClass(Vec::new())
        },
        _ => unreachable!("Unexpected rule {:?}", expr.as_rule()),
    }
}
