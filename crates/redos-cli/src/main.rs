use std::path::{Path, PathBuf};

use clap::Parser as ClapParser;
use ignore::WalkBuilder;
use redos::safe;
use swc_common::sync::Lrc;
use swc_common::{
    errors::{ColorConfig, Handler},
    SourceMap,
};
use swc_ecma_ast::Regex;
use swc_ecma_parser::{lexer::Lexer, Parser, StringInput, Syntax};
use swc_ecma_visit::{fold_module_item, Fold};

#[derive(ClapParser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[clap(short, long)]
    /// The directory to search for JavaScript files
    directory: Option<PathBuf>,
    #[clap(short, long)]
    /// The glob patterns to include
    include: Vec<String>,
    #[clap(short, long)]
    /// The glob patterns to exclude
    exclude: Vec<String>,
}

/// List of scanned extensions
const EXTENSIONS: [&str; 8] = ["js", "jsx", "ts", "tsx", "mjs", "cjs", "mts", "cts"];

fn main() {
    let args = Cli::parse();
    let walk = WalkBuilder::new(args.directory.unwrap_or_else(|| ".".into())).build();

    for entry in walk {
        let entry = entry.unwrap();

        if entry.file_type().unwrap().is_file() {
            let path = entry.path();

            if let Some(extension) = path.extension() {
                if EXTENSIONS.contains(&extension.to_str().unwrap()) {
                    check_file(path);
                }
            }
        }
    }
}

fn check_file(path: &Path) {
    let cm: Lrc<SourceMap> = Default::default();
    let handler = Handler::with_tty_emitter(ColorConfig::Auto, true, false, Some(cm.clone()));

    let fm = cm
        .load_file(path)
        .unwrap_or_else(|e| panic!("failed to load file: {}", e));

    let lexer = Lexer::new(
        Syntax::Es(Default::default()),
        Default::default(),
        StringInput::from(&*fm),
        None,
    );

    let mut parser = Parser::new_from(lexer);

    let module = parser
        .parse_module()
        .map_err(|e| {
            // Unrecoverable fatal error occurred
            e.into_diagnostic(&handler).emit()
        })
        .expect("failed to parser module");

    for token in module.body {
        fold_module_item(&mut Visitor, token);
    }
}

struct Visitor;

impl Fold for Visitor {
    fn fold_regex(&mut self, regex: Regex) -> Regex {
        if !safe(&regex.exp.to_string()) {
            println!("{}", regex.exp);
        }
        regex
    }
}
