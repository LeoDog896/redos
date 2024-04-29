#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Value {
    Singular(usize),
    Range(usize, usize),
}

impl Value {
    /// Matches a single character
    pub fn match_char(c: char) -> Value {
        Value::Singular(c as usize)
    }

    /// Parses a single character into a Value
    pub fn from_char(c: char) -> Value {
        if c == '.' {
            return Value::Range(0, usize::MAX);
        }

        Value::Singular(c as usize)
    }
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
        // This isn't a character class - just some single yes value
        if regex.len() == 1 {
            Token {
                yes: vec![Value::from_char(regex.chars().next().unwrap())],
                no: vec![],
                ignore_case,
            }
        } else {
            unimplemented!("No support for parsing character classes or multi-char tokens yet.")
        }
    }

    pub fn overlaps(&self, token: &Token) -> bool {
        unimplemented!("Can not detect overlapping tokens yet.")
    }
}
