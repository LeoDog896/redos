use std::path::Path;

use swc_common::sync::Lrc;
use swc_common::{
    errors::{ColorConfig, Handler},
    SourceMap,
};
use swc_ecma_ast::{EsVersion, Regex};
use swc_ecma_parser::TsConfig;
use swc_ecma_parser::{lexer::Lexer, Parser, StringInput, Syntax};
use swc_ecma_visit::{fold_module_item, Fold};

use anyhow::{anyhow, Result};

use async_trait::async_trait;

use super::language::{Language, Location};

/// List of scanned extensions
const EXTENSIONS: [&str; 8] = ["js", "jsx", "ts", "tsx", "mjs", "cjs", "mts", "cts"];

pub struct JavaScript;

#[async_trait(?Send)]
impl Language for JavaScript {
    async fn check_file(path: &Path) -> Result<Option<Vec<(String, Location)>>> {
        let ext = path.extension().unwrap_or_default();

        if !EXTENSIONS.contains(&ext.to_str().unwrap()) {
            return Ok(None);
        }

        let cm: Lrc<SourceMap> = Default::default();
        let handler = Handler::with_tty_emitter(ColorConfig::Auto, true, false, Some(cm.clone()));

        let fm = cm.load_file(path)?;

        let lexer = Lexer::new(
            Syntax::Typescript(TsConfig {
                tsx: true,
                decorators: true,
                dts: false,
                no_early_errors: true,
                disallow_ambiguous_jsx_like: false,
            }),
            EsVersion::latest(),
            StringInput::from(&*fm),
            None,
        );

        let mut parser = Parser::new_from(lexer);

        let module = parser
            .parse_module()
            .map_err(|e| {
                // Unrecoverable fatal error occurred
                e.into_diagnostic(&handler).emit();
            })
            .map_err(|_| anyhow!("Failed to parse file"))?;

        let (tx, mut rx) = tokio::sync::mpsc::channel(1);

        for token in module.body {
            let tx = tx.clone();
            fold_module_item(
                &mut Visitor {
                    callback: Box::new(move |regex| {
                        // regex_list.push(regex.to_string());
                        tx.blocking_send(regex).unwrap();
                    }),
                },
                token,
            );
        }

        let mut regex_list = vec![];

        while let Some(regex) = rx.recv().await {
            regex_list.push(regex);
        }

        Ok(Some(regex_list))
    }
}

struct Visitor {
    callback: Box<dyn Fn((String, Location))>,
}

impl Fold for Visitor {
    fn fold_regex(&mut self, regex: Regex) -> Regex {
        (self.callback)((
            regex.exp.as_ref().to_string(),
            Location {
                line: regex.span.lo.0 as usize,
                column: regex.span.hi.0 as usize,
            },
        ));
        regex
    }
}
