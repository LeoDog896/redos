use std::path::Path;

use anyhow::Result;

use ruff_python_parser::{lexer::lex, Mode};

use async_trait::async_trait;

use super::language::{Language, Location};

/// List of scanned extensions
const EXTENSIONS: [&str; 1] = ["py"];

pub struct Python;

#[async_trait(?Send)]
impl Language for Python {
    async fn check_file(path: &Path) -> Result<Option<Vec<(String, Location)>>> {
        let ext = path.extension().unwrap_or_default();

        if !EXTENSIONS.contains(&ext.to_str().unwrap()) {
            return Ok(None);
        }

        let contents = std::fs::read_to_string(path)?;

        let lexer = lex(&contents, Mode::Module);

        let regexes = vec![];

        for token in lexer {
            // TODO: support regexes
            println!("{:?}", token);
        }

        Ok(Some(regexes))
    }
}
