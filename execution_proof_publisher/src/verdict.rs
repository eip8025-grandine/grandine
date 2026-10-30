use core::fmt::{Display, Formatter, Result as FmtResult};
use std::process::ExitCode;

use serde::Serialize;

/// The verdict of one cell, one step or a whole run.
///
/// The order is the precedence when cells are combined: one `Fail` makes the
/// combination fail, and otherwise one `Inconclusive` makes it inconclusive.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Pass,
    Inconclusive,
    Fail,
}

impl Verdict {
    #[must_use]
    pub fn combine(verdicts: impl IntoIterator<Item = Self>) -> Self {
        verdicts.into_iter().max().unwrap_or(Self::Inconclusive)
    }

    #[must_use]
    pub fn exit_code(self) -> ExitCode {
        match self {
            Self::Pass => ExitCode::SUCCESS,
            Self::Fail => ExitCode::from(1),
            Self::Inconclusive => ExitCode::from(2),
        }
    }
}

impl Display for Verdict {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        let text = match self {
            Self::Pass => "pass",
            Self::Inconclusive => "inconclusive",
            Self::Fail => "fail",
        };

        formatter.write_str(text)
    }
}
