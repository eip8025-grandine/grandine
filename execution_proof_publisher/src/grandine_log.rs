//! Parses the Grandine log lines the evaluator relies on.
//!
//! Each line is matched by its body, after the log prefix. The time comes
//! from the prefix, which Grandine writes as `[RFC 3339 with milliseconds]`.
//!
//! - R1's per-type `info!` line in `runtime::execution_proofs`.
//! - The engine's verdict line in `proof_engine::zkvm_engine`, which carries
//!   the verdict, the rejection text and the type, but no block or validator.
//! - P1's terminal-outcome lines, logged at TRACE under
//!   `fork_choice_control`, with the bodies agreed with the P1 owner.

use std::sync::LazyLock;

use chrono::{DateTime, Utc};
use regex::Regex;
use types::{
    eip8025::primitives::ProofType,
    phase0::primitives::{H256, ValidatorIndex},
};

use crate::report::ProofKey;

/// The verdict Grandine's gossip validation gave a proof.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Outcome {
    Accept,
    Ignore { reason: String },
    Reject { reason: String },
}

/// How R1 reports it configured a proof type at startup.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Backend {
    Mock,
    Sp1 { program_vk: String },
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Event {
    Outcome {
        key: ProofKey,
        outcome: Outcome,
    },
    Engine {
        verdict: String,
        error: String,
        proof_type: ProofType,
    },
    Backend {
        proof_type: ProofType,
        backend: Backend,
    },
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Line {
    pub time: DateTime<Utc>,
    pub event: Event,
}

static ANSI_ESCAPE: LazyLock<Regex> = LazyLock::new(|| regex(r"\x1b\[[0-9;]*m"));

static TIME: LazyLock<Regex> = LazyLock::new(|| {
    regex(r"\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\]")
});

// `…` in the agreed bodies.
const KEY: &str = r"block_root: (0x[0-9a-f]{64}), proof_type: (\d+), validator_index: (\d+)";

static ACCEPTED: LazyLock<Regex> =
    LazyLock::new(|| regex(&format!(r"execution proof accepted \({KEY}\)")));

static IGNORED: LazyLock<Regex> = LazyLock::new(|| {
    regex(&format!(
        r"execution proof ignored \({KEY}, outcome: IGNORE, reason: ([^()]*)\)"
    ))
});

static REJECTED: LazyLock<Regex> = LazyLock::new(|| {
    regex(&format!(
        r"execution proof rejected \({KEY}, outcome: REJECT, reason: ([^()]*)\)"
    ))
});

static ENGINE: LazyLock<Regex> = LazyLock::new(|| {
    regex(
        r"execution proof (?:not accepted|could not be verified locally) \(verdict: (\w+), error: (.*), proof_type: (\d+)\)",
    )
});

static BACKEND: LazyLock<Regex> = LazyLock::new(|| {
    regex(
        r"execution proofs of type (\d+) are verified with (?:(zkboost mock verification)|SP1 verification against verifying key (0x[0-9a-f]{64}))",
    )
});

#[expect(clippy::expect_used, reason = "the patterns are constants")]
fn regex(pattern: &str) -> Regex {
    Regex::new(pattern).expect("pattern should be valid")
}

/// Parses every line the evaluator relies on and skips all others.
#[must_use]
pub fn parse(text: &str) -> Vec<Line> {
    text.lines().filter_map(parse_line).collect()
}

#[must_use]
pub fn parse_line(line: &str) -> Option<Line> {
    let line = ANSI_ESCAPE.replace_all(line, "");

    let time_match = TIME.captures(&line)?;
    let time = DateTime::parse_from_rfc3339(time_match.get(1)?.as_str())
        .ok()?
        .with_timezone(&Utc);

    let body = line.get(time_match.get(0)?.end()..)?;

    Some(Line {
        time,
        event: parse_body(body)?,
    })
}

fn parse_body(body: &str) -> Option<Event> {
    if let Some(captures) = ACCEPTED.captures(body) {
        return Some(Event::Outcome {
            key: key(&captures)?,
            outcome: Outcome::Accept,
        });
    }

    if let Some(captures) = IGNORED.captures(body) {
        return Some(Event::Outcome {
            key: key(&captures)?,
            outcome: Outcome::Ignore {
                reason: captures.get(4)?.as_str().to_owned(),
            },
        });
    }

    if let Some(captures) = REJECTED.captures(body) {
        return Some(Event::Outcome {
            key: key(&captures)?,
            outcome: Outcome::Reject {
                reason: captures.get(4)?.as_str().to_owned(),
            },
        });
    }

    if let Some(captures) = ENGINE.captures(body) {
        return Some(Event::Engine {
            verdict: captures.get(1)?.as_str().to_owned(),
            error: captures.get(2)?.as_str().to_owned(),
            proof_type: captures.get(3)?.as_str().parse().ok()?,
        });
    }

    if let Some(captures) = BACKEND.captures(body) {
        let proof_type = captures.get(1)?.as_str().parse().ok()?;

        let backend = match captures.get(3) {
            Some(program_vk) => Backend::Sp1 {
                program_vk: program_vk.as_str().to_owned(),
            },
            None => Backend::Mock,
        };

        return Some(Event::Backend {
            proof_type,
            backend,
        });
    }

    None
}

fn key(captures: &regex::Captures) -> Option<ProofKey> {
    let root_hex = captures.get(1)?.as_str().strip_prefix("0x")?;
    let root_bytes = hex::decode(root_hex).ok()?;

    Some(ProofKey {
        block_root: H256::from_slice(&root_bytes),
        proof_type: captures.get(2)?.as_str().parse().ok()?,
        validator_index: captures.get(3)?.as_str().parse::<ValidatorIndex>().ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn parses_colored_lines_with_fields_and_offsets() {
        let line = format!(
            "\x1b[2m[2026-10-30T14:00:01.250+02:00]\x1b[0m \x1b[35mTRACE\x1b[0m \
             fork_choice_control::mutator:2815: execution proof accepted \
             (block_root: {ROOT}, proof_type: 1, validator_index: 11) peers=4"
        );

        let parsed = parse_line(&line).expect("the line should parse");

        assert_eq!(
            parsed.time,
            DateTime::parse_from_rfc3339("2026-10-30T12:00:01.250Z")
                .expect("valid time")
                .with_timezone(&Utc),
        );
        assert_eq!(
            parsed.event,
            Event::Outcome {
                key: ProofKey {
                    block_root: H256::repeat_byte(0xbb),
                    proof_type: 1,
                    validator_index: 11,
                },
                outcome: Outcome::Accept,
            },
        );
    }

    #[test]
    fn parses_the_engine_line_with_nested_errors() {
        let line = "[2026-10-30T12:00:01.000Z] DEBUG proof_engine::zkvm_engine:257: \
                    execution proof not accepted (verdict: Invalid, error: proof failed \
                    verification: invalid (inner, detail), proof_type: 2)";

        assert_eq!(
            parse_line(line).map(|line| line.event),
            Some(Event::Engine {
                verdict: "Invalid".to_owned(),
                error: "proof failed verification: invalid (inner, detail)".to_owned(),
                proof_type: 2,
            }),
        );
    }

    #[test]
    fn ignores_lines_without_the_agreed_bodies() {
        let lines = [
            // Debug lines that carry no identifiers.
            "[2026-10-30T12:00:01.000Z] DEBUG fork_choice_control::mutator:2860: \
             execution proof ignored (reason: execution proof admission declined)",
            "[2026-10-30T12:00:01.000Z] WARN fork_choice_control::mutator:2875: \
             execution proof rejected (error: invalid signature)",
            "no timestamp: execution proofs of type 1 are verified with zkboost mock verification",
        ];

        for line in lines {
            assert_eq!(parse_line(line), None, "{line}");
        }
    }
}
