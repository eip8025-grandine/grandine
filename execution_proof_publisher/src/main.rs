//! A devnet tool that publishes EIP-8025 execution proofs to one Grandine
//! node over gossip and evaluates how the node handled them.
//!
//! `run` publishes the messages of design 0012 and writes a JSONL report.
//! `evaluate` reads that report and Grandine's log, prints the step table and
//! exits 0 (pass), 1 (a condition is contradicted) or 2 (inconclusive).

use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};
use kzg_utils as _;
use tracing::error;
use tracing_subscriber::EnvFilter;
use types::preset::Mainnet;

use crate::{evaluate::EvaluateArgs, run::RunArgs, verdict::Verdict};

mod beacon;
mod chain;
mod evaluate;
mod grandine_log;
mod identity;
mod keys;
mod messages;
mod report;
mod run;
mod target;
mod verdict;

#[cfg(test)]
mod tests;

#[derive(Parser)]
#[clap(about, version)]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Publish the steps against a running devnet and write the report.
    Run(RunArgs),
    /// Evaluate a report and Grandine's log, and set the exit code.
    Evaluate(EvaluateArgs),
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_env("PUBLISHER_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let result: Result<Verdict> = match Cli::parse().command {
        // The devnet uses the mainnet preset.
        Command::Run(args) => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(Into::into)
            .and_then(|runtime| runtime.block_on(run::run::<Mainnet>(args))),
        Command::Evaluate(args) => evaluate::run(&args),
    };

    match result {
        Ok(verdict) => verdict.exit_code(),
        Err(error) => {
            error!("{error:?}");
            Verdict::Inconclusive.exit_code()
        }
    }
}
