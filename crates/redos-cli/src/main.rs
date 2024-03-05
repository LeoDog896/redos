mod languages;
mod repo;

use std::path::{Path, PathBuf};

use clap::{Parser as ClapParser, Subcommand};
use fancy_regex::parse::Parser as FancyParser;
use ignore::WalkBuilder;
use languages::{
    javascript::JavaScript,
    language::{Language, Location},
};
use owo_colors::OwoColorize;
use redos::vulnerabilities;
use repo::parse_repository;
use tempdir::TempDir;

use anyhow::Result;

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
    Ast {
        /// The regex to parse
        regex: String,
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

fn print_regex(regex: &str, location: Location, raw: bool, path: &Path) {
    if raw {
        println!("{}", regex);
    } else {
        println!("{}:{}", path.to_str().unwrap(), location);
        println!("  {}", regex.red());
    }
}

async fn local_scan(all: bool, raw: bool, directory: Option<PathBuf>) -> Result<()> {
    let walk = WalkBuilder::new(directory.unwrap_or_else(|| ".".into())).build();

    for entry in walk {
        let entry = entry.unwrap();

        if entry.file_type().unwrap().is_file() {
            let path = entry.path();

            let regexes = JavaScript::check_file(path).await?;

            if let Some(regexes) = regexes {
                for regex in regexes {
                    if all
                        || !vulnerabilities(&regex.0, &Default::default())?
                            .vulnerabilities
                            .is_empty()
                    {
                        print_regex(&regex.0, regex.1, raw, path);
                    }
                }
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
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
                local_scan(all, raw, directory).await?;
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

                local_scan(all, raw, Some(directory.into_path())).await?;
            }
        },
        Commands::Ast { regex } => {
            println!("{:#?}", FancyParser::parse(regex.as_str()));
        }
    }

    Ok(())
}
