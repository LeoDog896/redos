use anyhow::Result;
use async_trait::async_trait;
use std::fmt::Display;
use std::path::Path;

#[derive(Debug)]
pub struct Location {
    pub line: usize,
    pub column: usize,
}

impl Display for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.line, self.column)
    }
}

#[async_trait(?Send)]
pub trait Language {
    /// Scans a file for every known regex.
    /// Returns None if the file is not supported.
    ///
    /// Else, returns a list of regexes and their location in the file.
    async fn check_file(path: &Path) -> Result<Option<Vec<(String, Location)>>>;
}
