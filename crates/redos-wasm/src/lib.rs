use wasm_bindgen::prelude::*;
use fancy_regex::parse::Parser;

#[wasm_bindgen]
pub fn parse(regex: &str) -> String {
    format!("{:#?}", Parser::parse(regex))
}

#[wasm_bindgen]
pub fn vulnerabilities(regex: &str) -> String {
    format!("{:#?}", redos::vulnerabilities(regex))
}
