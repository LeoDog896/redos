#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Value {
    Singular(String),
    Range(String, String),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Token {
    /// Singular tokens that can be matched in this token
    pub yes: Vec<Value>,
    /// Singular tokens that can't be matched in this token
    pub no: Vec<Value>,
    /// Whether comparisons care about ignoring case
    pub ignore_case: bool,
}

impl Token {
    /// Creates a new token.
    /// Takes in a basic regex that is either a single character
    /// or a character class.
    pub fn new(regex: &str) -> Token {
        Self::new_case(regex, false)
    }

    pub fn new_case(regex: &str, ignore_case: bool) -> Token {
        if !(regex.contains('[') || regex.contains(']')) {
            // This isn't a character class - just a single character
            Token {
                yes: vec![Value::Singular(regex.to_string())],
                no: vec![],
                ignore_case,
            }
        } else {
            unimplemented!("No support for parsing character classes yet.")
        }
    }

    fn overlaps(&self, token: &Token) -> bool {
        unimplemented!("Can not detect overlapping tokens yet.")
    }
}
