use std::path::PathBuf;

use nom::{
    bytes::complete::tag,
    character::complete::alphanumeric1,
    combinator::{eof, map_res, opt},
    sequence::{preceded, terminated},
    IResult,
};

use anyhow::{anyhow, Result};

#[derive(Debug, PartialEq, Eq)]
pub enum Host {
    GitHub,
    GitLab,
    BitBucket,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Reference {
    Branch(String),
    Tag(String),
    Commit(String),
    Head,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Repository {
    owner: String,
    name: String,
    reference: Reference,
    host: Host,
}

fn word(input: &str) -> IResult<&str, &str> {
    alphanumeric1(input)
}

/// Parses a repository string into a Repository struct.
///
/// The default Host is GitHub.
///
/// Format: [host]:[owner]/[name]#[reference]
pub fn parse_repository(i: &str) -> IResult<&str, Repository> {
    let (i, host) = map_res(opt(terminated(word, tag(":"))), |h| match h {
        None | Some("github") => Ok(Host::GitHub),
        Some("gitlab") => Ok(Host::GitLab),
        Some("bitbucket") => Ok(Host::BitBucket),
        _ => Err(anyhow!("Invalid host")),
    })(i)?;
    let (i, owner) = terminated(word, tag("/"))(i)?;
    let (i, name) = word(i)?;
    // TODO: parse reference - possible method is git ls-remote
    let (i, _) = opt(preceded(tag("#"), word))(i)?;
    let (i, _) = eof(i)?;

    Ok((
        i,
        Repository {
            host,
            owner: owner.to_string(),
            name: name.to_string(),
            // TODO: parse reference
            reference: Reference::Head,
        },
    ))
}

pub fn download_repository(repository: &Repository, directory: PathBuf) -> Result<()> {
    let url = match repository.host {
        Host::GitHub => format!(
            "https://github.com/{}/{}/archive/HEAD.tar.gz",
            repository.owner, repository.name
        ),
        Host::GitLab => format!(
            "https://gitlab.com/{}/{}/-/archive/HEAD/{}.tar.gz",
            repository.owner, repository.name, repository.name
        ),
        Host::BitBucket => format!(
            "https://bitbucket.org/{}/{}/get/HEAD.zip",
            repository.owner, repository.name
        ),
    };

    println!("Fetching {url}...");

    let bytes = reqwest::blocking::get(&url)?.bytes()?;

    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(&*bytes));

    archive.unpack(directory)?;

    Ok(())
}
