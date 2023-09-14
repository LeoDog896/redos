use pest::Parser;
use pest::iterators::Pair;
use pest::error::Error;
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "regex.pest"]
struct RegexParser;

pub fn as_ast(input: &str) -> Result<Pair<'_, Rule>, Error<Rule>> {
    let regex = RegexParser::parse(Rule::regex, input)?.next().unwrap();

    Ok(regex)
}

fn parse(input: &str) -> Result<(), Error<Rule>> {
    let regex = RegexParser::parse(Rule::regex, input)?.next().unwrap();

    match regex.as_rule() {
        Rule::regex => {

        },
        _ => unreachable!()
    }

    Ok(())
}