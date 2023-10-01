use core::panic;
use std::path::{Path, PathBuf};

use clap::Parser as ClapParser;
use ignore::WalkBuilder;
use redos::vulnerabilities;
use swc_common::sync::Lrc;
use swc_common::{
    errors::{ColorConfig, Handler},
    SourceMap,
};
use swc_ecma_ast::{EsVersion, Regex};
use swc_ecma_parser::TsConfig;
use swc_ecma_parser::{lexer::Lexer, Parser, StringInput, Syntax};
use swc_ecma_visit::{fold_module_item, Fold};

#[derive(ClapParser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[clap(short, long)]
    /// The directory to search for JavaScript files
    directory: Option<PathBuf>,
    #[clap(short, long)]
    /// Show every regex
    all: bool,
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
                    check_file(path, args.all);
                }
            }
        }
    }
}

fn check_file(path: &Path, show_all: bool) {
    let cm: Lrc<SourceMap> = Default::default();
    let handler = Handler::with_tty_emitter(ColorConfig::Auto, true, false, Some(cm.clone()));

    let fm = cm
        .load_file(path)
        .unwrap_or_else(|e| panic!("failed to load file: {}", e));

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

    let module = parser.parse_module().map_err(|e| {
        // Unrecoverable fatal error occurred
        e.into_diagnostic(&handler).emit()
    });

    match module {
        Ok(module) => {
            for token in module.body {
                fold_module_item(&mut Visitor { show_all }, token);
            }
        }
        Err(_) => (),
    }
}

struct Visitor {
    show_all: bool,
}

impl Fold for Visitor {
    fn fold_regex(&mut self, regex: Regex) -> Regex {
        if !vulnerabilities(&regex.exp.to_string()).is_empty() || self.show_all {
            println!("{}", regex.exp);
        }
        regex
    }
}
