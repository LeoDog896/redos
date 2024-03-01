use fancy_regex::parse::Parser;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn parse(regex: &str) -> String {
    format!("{:#?}", Parser::parse(regex))
}

#[wasm_bindgen]
pub fn ir(regex: &str) -> String {
    let parser = Parser::parse(regex);
    format!(
        "{:#?}",
        parser.map(|tree| redos::ir::to_expr(&tree, &tree.expr))
    )
}

#[wasm_bindgen]
pub fn vulnerabilities(regex: &str) -> String {
    format!(
        "{:#?}",
        redos::vulnerabilities(regex, &Default::default()).map(|r| r.vulnerabilities)
    )
}
