use core::fmt::{Display, Formatter, Result as FmtResult};
use std::{
    io::{BufRead as _, BufReader, Write as _},
    path::Path,
};

use anyhow::{Context as _, Result};
use chrono::{DateTime, Utc};
use fs_err::File;
use serde::{Deserialize, Serialize};
use types::{
    eip8025::primitives::ProofType,
    phase0::primitives::{H256, ValidatorIndex},
};

use crate::target::{Eligibility, Target};

/// One of the publisher's four `eth2_libp2p` identities.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Deserialize, Serialize)]
pub enum Role {
    /// The observer. It subscribes and never publishes.
    O,
    /// Publishes steps 1 and 2.
    #[serde(rename = "P_a")]
    Pa,
    /// Publishes step 3.
    #[serde(rename = "P_b")]
    Pb,
    /// Publishes step 4.
    #[serde(rename = "P_c")]
    Pc,
}

impl Role {
    pub const ALL: [Self; 4] = [Self::O, Self::Pa, Self::Pb, Self::Pc];
}

impl Display for Role {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        let text = match self {
            Self::O => "O",
            Self::Pa => "P_a",
            Self::Pb => "P_b",
            Self::Pc => "P_c",
        };

        formatter.write_str(text)
    }
}

/// What identifies an incoming proof in Grandine's outcome lines.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Deserialize, Serialize)]
pub struct ProofKey {
    pub block_root: H256,
    pub proof_type: ProofType,
    pub validator_index: ValidatorIndex,
}

impl Display for ProofKey {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        write!(
            formatter,
            "({:?}, {}, {})",
            self.block_root, self.proof_type, self.validator_index,
        )
    }
}

/// When an eligibility check ran relative to its step.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckPoint {
    BeforePublish,
    AfterWindow,
}

/// One line of the JSONL report.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Record {
    RunStarted {
        #[serde(with = "rfc3339")]
        time: DateTime<Utc>,
        grandine_peer_id: String,
        chain_id: u64,
        window_ms: u64,
        margin_ms: u64,
    },
    Identity {
        #[serde(with = "rfc3339")]
        time: DateTime<Utc>,
        role: Role,
        peer_id: String,
    },
    Connection {
        #[serde(with = "rfc3339")]
        time: DateTime<Utc>,
        role: Role,
        peer_id: String,
        connected: bool,
    },
    /// The identity saw Grandine subscribe to the `execution_proof` topic.
    GrandineSubscribed {
        #[serde(with = "rfc3339")]
        time: DateTime<Utc>,
        role: Role,
    },
    /// The identity's mesh for the `execution_proof` topic changed.
    Mesh {
        #[serde(with = "rfc3339")]
        time: DateTime<Utc>,
        role: Role,
        peers: Vec<String>,
    },
    Target {
        #[serde(with = "rfc3339")]
        time: DateTime<Utc>,
        target: Target,
    },
    Eligibility {
        #[serde(with = "rfc3339")]
        time: DateTime<Utc>,
        step: u8,
        point: CheckPoint,
        target: Target,
        result: Eligibility,
    },
    Publish {
        #[serde(with = "rfc3339")]
        time: DateTime<Utc>,
        step: u8,
        role: Role,
        key: ProofKey,
        envelope_root: H256,
        message_id: Option<String>,
        ssz_sha256: String,
        error: Option<String>,
    },
    Receipt {
        #[serde(with = "rfc3339")]
        time: DateTime<Utc>,
        role: Role,
        source: String,
        message_id: String,
        key: ProofKey,
        envelope_root: H256,
        ssz_sha256: String,
    },
    /// How long a step waited after publishing.
    ///
    /// `planned_end` is the publish time plus W. `end` is earlier if O
    /// received the step's message first.
    Window {
        step: u8,
        #[serde(with = "rfc3339")]
        start: DateTime<Utc>,
        #[serde(with = "rfc3339")]
        planned_end: DateTime<Utc>,
        #[serde(with = "rfc3339")]
        end: DateTime<Utc>,
    },
    /// The run stopped before the remaining steps.
    Stopped {
        #[serde(with = "rfc3339")]
        time: DateTime<Utc>,
        step: u8,
        reason: String,
    },
    RunFinished {
        #[serde(with = "rfc3339")]
        time: DateTime<Utc>,
    },
}

pub struct ReportWriter {
    file: File,
}

impl ReportWriter {
    pub fn create(path: &Path) -> Result<Self> {
        Ok(Self {
            file: File::create(path)?,
        })
    }

    pub fn write(&mut self, record: &Record) -> Result<()> {
        let mut line = serde_json::to_vec(record)?;
        line.push(b'\n');
        self.file.write_all(&line)?;
        self.file.flush()?;
        Ok(())
    }
}

pub fn read(path: &Path) -> Result<Vec<Record>> {
    BufReader::new(File::open(path)?)
        .lines()
        .enumerate()
        .filter(|(_, line)| line.as_ref().map_or(true, |line| !line.trim().is_empty()))
        .map(|(index, line)| {
            serde_json::from_str(&line?)
                .with_context(|| format!("report line {} is not a record", index.saturating_add(1)))
        })
        .collect()
}

// `chrono`'s `serde` feature is not enabled in the workspace. Enabling it here
// would also change the `grandine` binary's build through feature unification.
mod rfc3339 {
    use chrono::{DateTime, SecondsFormat, Utc};
    use serde::{Deserialize as _, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(
        time: &DateTime<Utc>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&time.to_rfc3339_opts(SecondsFormat::Millis, true))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<DateTime<Utc>, D::Error> {
        let string = String::deserialize(deserializer)?;

        DateTime::parse_from_rfc3339(&string)
            .map(|time| time.with_timezone(&Utc))
            .map_err(D::Error::custom)
    }
}
