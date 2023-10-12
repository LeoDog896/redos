mod repo;

use core::panic;
use std::path::{Path, PathBuf};

use clap::{Parser as ClapParser, Subcommand};
use ignore::WalkBuilder;
use owo_colors::OwoColorize;
use redos::vulnerabilities;
use repo::parse_repository;
use swc_common::sync::Lrc;
use swc_common::{
    errors::{ColorConfig, Handler},
    SourceMap,
};
use swc_ecma_ast::{EsVersion, Regex};
use swc_ecma_parser::TsConfig;
use swc_ecma_parser::{lexer::Lexer, Parser, StringInput, Syntax};
use swc_ecma_visit::{fold_module_item, Fold};
use tempdir::TempDir;

use crate::repo::download_repository;

#[derive(ClapParser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Scan {
        #[command(subcommand)]
        command: ScanCommand,
    },
}

#[derive(Subcommand)]
enum ScanCommand {
    Local {
        /// The directory to search for files
        directory: Option<PathBuf>,
        #[clap(short, long)]
        /// Show every regex
        all: bool,
        /// Display them raw
        #[clap(short, long)]
        raw: bool,
        #[clap(short, long)]
        /// The glob patterns to include
        include: Vec<String>,
        #[clap(short, long)]
        /// The glob patterns to exclude
        exclude: Vec<String>,
    },
    Git {
        /// The repository to scan
        repository: String,
        /// Show every regex
        #[clap(short, long)]
        all: bool,
        /// Display them raw
        #[clap(short, long)]
        raw: bool,
    },
}

/// List of scanned extensions
const EXTENSIONS: [&str; 8] = ["js", "jsx", "ts", "tsx", "mjs", "cjs", "mts", "cts"];

fn local_scan(all: bool, raw: bool, directory: Option<PathBuf>) {
    let walk = WalkBuilder::new(directory.unwrap_or_else(|| ".".into())).build();

    for entry in walk {
        let entry = entry.unwrap();

        if entry.file_type().unwrap().is_file() {
            let path = entry.path();

            if let Some(extension) = path.extension() {
                if EXTENSIONS.contains(&extension.to_str().unwrap()) {
                    check_file(path, raw, all);
                }
            }
        }
    }
}

fn main() {
    let args = Cli::parse();
    match args.command {
        Commands::Scan { command } => match command {
            ScanCommand::Local {
                all,
                directory,
                include: _,
                exclude: _,
                raw,
            } => {
                local_scan(all, raw, directory);
            }
            ScanCommand::Git {
                repository,
                all,
                raw,
            } => {
                let (_, repository) = parse_repository(&repository).unwrap();
                let directory = TempDir::new("redos").unwrap();
                download_repository(&repository, directory.path().to_path_buf()).unwrap();
                println!(
                    "Downloaded repository to {}",
                    directory.path().to_str().unwrap()
                );

                local_scan(all, raw, Some(directory.into_path()));
            }
        },
    }
}

fn check_file(path: &Path, raw: bool, show_all: bool) {
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
        e.into_diagnostic(&handler).emit();
    });

    if let Ok(module) = module {
        for token in module.body {
            fold_module_item(
                &mut Visitor {
                    show_all,
                    raw,
                    path: path.into(),
                },
                token,
            );
        }
    }
}

struct Visitor {
    show_all: bool,
    path: PathBuf,
    raw: bool,
}

impl Fold for Visitor {
    fn fold_regex(&mut self, regex: Regex) -> Regex {
        if self.show_all || !vulnerabilities(regex.exp.as_ref()).is_empty() {
            if self.raw {
                println!("{}", regex.exp);
            } else {
                println!("{}", self.path.to_str().unwrap());
                println!("  {}", regex.exp.red());
            }
        }
        regex
    }
}
