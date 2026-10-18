//! Development tasks, run as `cargo xtask <task>`.
//!
//! ```text
//! cargo xtask keys generate --store <file> --alg <ALG> [--kid <KID>]
//! ```

use std::path::PathBuf;
use std::process::ExitCode;

use identity_kit::jose::{JwsAlgorithm, KeyType};
use identity_kit::keys::{KeySpec, KeyStore, SoftwareKeyStore, SoftwareKeyStoreOptions};

const USAGE: &str = "\
Usage: cargo xtask <task>

Tasks:
  keys generate --store <file> --alg <ALG> [--kid <KID>]
      Generate a key in the JWK set file <file>, creating the file if it does not exist,
      and print the public JWK. <ALG> is EdDSA, ES256 or ES256K. The key id is <KID>
      when given and the RFC 7638 thumbprint of the public key otherwise.
";

fn main() -> ExitCode {
    match run(lexopt::Parser::from_env()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Error::Usage(message)) => {
            eprintln!("error: {message}\n\n{USAGE}");
            ExitCode::from(2)
        }
        Err(Error::Failed(message)) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

enum Error {
    Usage(String),
    Failed(String),
}

impl From<lexopt::Error> for Error {
    fn from(e: lexopt::Error) -> Self {
        Self::Usage(e.to_string())
    }
}

fn run(mut parser: lexopt::Parser) -> Result<(), Error> {
    use lexopt::prelude::*;
    let task = match parser.next()? {
        Some(Value(task)) => task,
        Some(Long("help") | Short('h')) => {
            print!("{USAGE}");
            return Ok(());
        }
        Some(other) => return Err(other.unexpected().into()),
        None => return Err(Error::Usage("no task given".to_owned())),
    };
    match task.to_str() {
        Some("keys") => keys(parser),
        _ => Err(Error::Usage(format!("unknown task {task:?}"))),
    }
}

fn keys(mut parser: lexopt::Parser) -> Result<(), Error> {
    use lexopt::prelude::*;
    let subcommand = match parser.next()? {
        Some(Value(subcommand)) => subcommand,
        Some(other) => return Err(other.unexpected().into()),
        None => return Err(Error::Usage("`keys` needs a subcommand".to_owned())),
    };
    if subcommand.to_str() != Some("generate") {
        return Err(Error::Usage(format!(
            "unknown `keys` subcommand {subcommand:?}"
        )));
    }

    let mut store: Option<PathBuf> = None;
    let mut alg: Option<JwsAlgorithm> = None;
    let mut kid: Option<String> = None;
    while let Some(arg) = parser.next()? {
        match arg {
            Long("store") => store = Some(parser.value()?.into()),
            Long("alg") => {
                let value = parser.value()?.string()?;
                alg = Some(
                    value
                        .parse()
                        .map_err(|_| Error::Usage(format!("unknown algorithm `{value}`")))?,
                );
            }
            Long("kid") => kid = Some(parser.value()?.string()?),
            Long("help") | Short('h') => {
                print!("{USAGE}");
                return Ok(());
            }
            other => return Err(other.unexpected().into()),
        }
    }
    let store = store.ok_or_else(|| Error::Usage("`--store <file>` is required".to_owned()))?;
    let alg = alg.ok_or_else(|| Error::Usage("`--alg <ALG>` is required".to_owned()))?;
    let key_type = match alg {
        JwsAlgorithm::EdDSA => KeyType::Ed25519,
        JwsAlgorithm::ES256 => KeyType::P256,
        JwsAlgorithm::ES256K => KeyType::Secp256k1,
        other => {
            return Err(Error::Usage(format!(
                "cannot generate software keys for {other}; use EdDSA, ES256 or ES256K"
            )));
        }
    };

    let store = SoftwareKeyStore::open_with(
        store,
        SoftwareKeyStoreOptions::new().create_if_missing(true),
    )
    .map_err(|e| Error::Failed(e.to_string()))?;
    let mut spec = KeySpec::new(key_type, alg);
    if let Some(kid) = kid {
        spec = spec.with_label(kid);
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|e| Error::Failed(e.to_string()))?;
    let public = runtime
        .block_on(async {
            let id = store.generate(spec).await?;
            store.public_jwk(&id).await
        })
        .map_err(|e| Error::Failed(e.to_string()))?;
    // A `Jwk` always serializes.
    let json = serde_json::to_string_pretty(&public).map_err(|e| Error::Failed(e.to_string()))?;
    println!("{json}");
    Ok(())
}
