//! Evaluates a run from its report and Grandine's log.
//!
//! Every cell of the step table is pass, fail or inconclusive. The run
//! passes only if every cell passes, fails if any cell is contradicted, and
//! is otherwise inconclusive.

use core::time::Duration;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

use anyhow::Result;
use chrono::{DateTime, TimeDelta, Utc};
use clap::Args;
use serde::Serialize;

use crate::{
    grandine_log::{self, Backend, Event, Line, Outcome},
    messages::{MOCK_PROOF_TYPE, SP1_PROOF_TYPE},
    report::{self, ProofKey, Record, Role},
    verdict::Verdict,
};

/// The guest VK of the SP1 fixture, as R1 logs it.
pub const EXPECTED_SP1_VK: &str =
    "0x00662ca6c9db4ecb22d9ac4c320612caeac9c320f92e3ab019af4f544e35c88b";

/// The reasons that mean (B, 1) already holds a verified proof.
///
/// The first is the preparation precheck's spec text. The second is the
/// Store's enum name, logged by live admission and by completion.
pub const ALREADY_VERIFIED_REASONS: [&str; 2] = [
    "verified proof already known for this beacon block and proof type",
    "AlreadyVerified",
];

/// The reasons that mean B's eligibility changed.
pub const RETIREMENT_REASONS: [&str; 2] = ["Retired", "ContextInapplicable"];

pub const REJECT_REASON: &str = "invalid execution proof";

const PUBLIC_VALUES_MISMATCH: &str = "committed public values do not match the public input";
const VERIFICATION_FAILURE: &str = "proof failed verification";

#[derive(Args)]
pub struct EvaluateArgs {
    /// The JSONL report written by `run`.
    #[clap(long)]
    report: PathBuf,
    /// Grandine's log, as `kurtosis service logs` saved it.
    #[clap(long)]
    log: PathBuf,
    /// Where to write the verdict as JSON.
    #[clap(long)]
    verdict: Option<PathBuf>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct Cell {
    pub verdict: Verdict,
    pub detail: String,
}

impl Cell {
    fn pass(detail: impl Into<String>) -> Self {
        Self {
            verdict: Verdict::Pass,
            detail: detail.into(),
        }
    }

    fn fail(detail: impl Into<String>) -> Self {
        Self {
            verdict: Verdict::Fail,
            detail: detail.into(),
        }
    }

    fn inconclusive(detail: impl Into<String>) -> Self {
        Self {
            verdict: Verdict::Inconclusive,
            detail: detail.into(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct StepResult {
    pub step: u8,
    pub sender: String,
    pub grandine: Cell,
    /// `None` for step 0, which has nothing to observe at O.
    pub at_o: Option<Cell>,
}

impl StepResult {
    fn verdict(&self) -> Verdict {
        Verdict::combine(
            core::iter::once(self.grandine.verdict)
                .chain(self.at_o.as_ref().map(|cell| cell.verdict)),
        )
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct Evaluation {
    pub verdict: Verdict,
    pub steps: Vec<StepResult>,
}

pub fn run(args: &EvaluateArgs) -> Result<Verdict> {
    let records = report::read(&args.report)?;
    let log = grandine_log::parse(&fs_err::read_to_string(&args.log)?);
    let evaluation = evaluate(&records, &log);

    let mut stdout = std::io::stdout().lock();
    write_table(&mut stdout, &evaluation)?;

    if let Some(path) = &args.verdict {
        fs_err::write(path, serde_json::to_vec_pretty(&evaluation)?)?;
    }

    Ok(evaluation.verdict)
}

fn write_table(output: &mut impl std::io::Write, evaluation: &Evaluation) -> Result<()> {
    writeln!(
        output,
        "| Step | Sender, validator | Grandine evidence | At O |"
    )?;
    writeln!(output, "| --- | --- | --- | --- |")?;

    for step in &evaluation.steps {
        let at_o = step.at_o.as_ref().map_or_else(
            || "—".to_owned(),
            |cell| format!("{}: {}", cell.verdict, cell.detail),
        );

        writeln!(
            output,
            "| {} | {} | {}: {} | {} |",
            step.step, step.sender, step.grandine.verdict, step.grandine.detail, at_o,
        )?;
    }

    writeln!(output)?;
    writeln!(output, "verdict: {}", evaluation.verdict)?;

    Ok(())
}

/// What a step publishes and what Grandine must do with it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Expectation {
    /// Step 1: ACCEPT, and O receives the message from Grandine.
    Accept,
    /// Step 2: IGNORE with an already-verified reason, and nothing at O.
    AlreadyVerified,
    /// Step 3: REJECT, with the engine's binding failure.
    RejectBinding,
    /// Step 4: REJECT, with the engine's verification failure.
    RejectVerification,
}

struct StepSpec {
    step: u8,
    role: Role,
    proof_type: u8,
    expectation: Expectation,
}

const STEPS: [StepSpec; 4] = [
    StepSpec {
        step: 1,
        role: Role::Pa,
        proof_type: MOCK_PROOF_TYPE,
        expectation: Expectation::Accept,
    },
    StepSpec {
        step: 2,
        role: Role::Pa,
        proof_type: MOCK_PROOF_TYPE,
        expectation: Expectation::AlreadyVerified,
    },
    StepSpec {
        step: 3,
        role: Role::Pb,
        proof_type: SP1_PROOF_TYPE,
        expectation: Expectation::RejectBinding,
    },
    StepSpec {
        step: 4,
        role: Role::Pc,
        proof_type: SP1_PROOF_TYPE,
        expectation: Expectation::RejectVerification,
    },
];

struct Publish<'report> {
    time: DateTime<Utc>,
    key: ProofKey,
    message_id: Option<&'report str>,
    ssz_sha256: &'report str,
    error: Option<&'report str>,
}

struct Window {
    start: DateTime<Utc>,
    planned_end: DateTime<Utc>,
    end: DateTime<Utc>,
}

struct Receipt<'report> {
    time: DateTime<Utc>,
    source: &'report str,
    message_id: &'report str,
    key: ProofKey,
    ssz_sha256: &'report str,
}

/// The report, indexed for evaluation.
struct Run<'report> {
    grandine_peer_id: &'report str,
    margin: TimeDelta,
    publishes: BTreeMap<u8, Publish<'report>>,
    windows: BTreeMap<u8, Window>,
    eligibility_failures: BTreeSet<u8>,
    eligibility_checks: BTreeMap<u8, usize>,
    stopped: Option<(u8, &'report str)>,
    receipts: Vec<Receipt<'report>>,
    foreign_peers_at_o: BTreeSet<&'report str>,
    subscribed: BTreeMap<Role, DateTime<Utc>>,
    mesh_at_o: Vec<(DateTime<Utc>, bool)>,
}

impl<'report> Run<'report> {
    fn index(records: &'report [Record]) -> Option<Self> {
        let (grandine_peer_id, margin) = records.iter().find_map(|record| match record {
            Record::RunStarted {
                grandine_peer_id,
                margin_ms,
                ..
            } => Some((
                grandine_peer_id.as_str(),
                TimeDelta::from_std(Duration::from_millis(*margin_ms)).ok()?,
            )),
            _ => None,
        })?;

        let mut run = Self {
            grandine_peer_id,
            margin,
            publishes: BTreeMap::new(),
            windows: BTreeMap::new(),
            eligibility_failures: BTreeSet::new(),
            eligibility_checks: BTreeMap::new(),
            stopped: None,
            receipts: vec![],
            foreign_peers_at_o: BTreeSet::new(),
            subscribed: BTreeMap::new(),
            mesh_at_o: vec![],
        };

        for record in records {
            run.add(record);
        }

        Some(run)
    }

    fn add(&mut self, record: &'report Record) {
        match record {
            Record::Publish {
                time,
                step,
                key,
                message_id,
                ssz_sha256,
                error,
                ..
            } => {
                self.publishes.insert(
                    *step,
                    Publish {
                        time: *time,
                        key: *key,
                        message_id: message_id.as_deref(),
                        ssz_sha256,
                        error: error.as_deref(),
                    },
                );
            }
            Record::Window {
                step,
                start,
                planned_end,
                end,
            } => {
                self.windows.insert(
                    *step,
                    Window {
                        start: *start,
                        planned_end: *planned_end,
                        end: *end,
                    },
                );
            }
            Record::Eligibility { step, result, .. } => {
                let checks = self.eligibility_checks.entry(*step).or_default();
                *checks = checks.saturating_add(1);

                if !result.is_eligible() {
                    self.eligibility_failures.insert(*step);
                }
            }
            Record::Stopped { step, reason, .. } => {
                self.stopped.get_or_insert((*step, reason));
            }
            Record::Receipt {
                time,
                role: Role::O,
                source,
                message_id,
                key,
                ssz_sha256,
                ..
            } => self.receipts.push(Receipt {
                time: *time,
                source,
                message_id,
                key: *key,
                ssz_sha256,
            }),
            Record::Connection {
                role: Role::O,
                peer_id,
                connected: true,
                ..
            } if peer_id != self.grandine_peer_id => {
                self.foreign_peers_at_o.insert(peer_id);
            }
            Record::GrandineSubscribed { time, role } => {
                self.subscribed.entry(*role).or_insert(*time);
            }
            Record::Mesh {
                time,
                role: Role::O,
                peers,
            } => self.mesh_at_o.push((
                *time,
                peers.iter().any(|peer| peer == self.grandine_peer_id),
            )),
            _ => {}
        }
    }

    fn published_keys(&self) -> BTreeSet<ProofKey> {
        self.publishes.values().map(|publish| publish.key).collect()
    }
}

#[must_use]
pub fn evaluate(records: &[Record], log: &[Line]) -> Evaluation {
    let Some(run) = Run::index(records) else {
        let steps = core::iter::once(step_0_result(Cell::inconclusive("the report has no run")))
            .chain(STEPS.iter().map(|spec| StepResult {
                step: spec.step,
                sender: spec.role.to_string(),
                grandine: Cell::inconclusive("not run"),
                at_o: Some(Cell::inconclusive("not run")),
            }))
            .collect();

        return finish(steps);
    };

    let step_0 = evaluate_step_0(&run, log);
    let observer_ready = step_0.verdict == Verdict::Pass;

    let steps = core::iter::once(step_0_result(step_0))
        .chain(
            STEPS
                .iter()
                .map(|spec| evaluate_step(&run, log, spec, observer_ready)),
        )
        .collect();

    finish(steps)
}

fn finish(steps: Vec<StepResult>) -> Evaluation {
    Evaluation {
        verdict: Verdict::combine(steps.iter().map(StepResult::verdict)),
        steps,
    }
}

fn step_0_result(cell: Cell) -> StepResult {
    StepResult {
        step: 0,
        sender: "all".to_owned(),
        grandine: cell,
        at_o: None,
    }
}

/// Step 0: R1's startup lines, Grandine subscribed as all four identities
/// see it, Grandine in O's mesh, and no other peer at O.
fn evaluate_step_0(run: &Run, log: &[Line]) -> Cell {
    let mut problems = vec![];

    let backend = |proof_type| {
        log.iter().find_map(|line| match &line.event {
            Event::Backend {
                proof_type: logged,
                backend,
            } if *logged == proof_type => Some(backend.clone()),
            _ => None,
        })
    };

    match backend(MOCK_PROOF_TYPE) {
        Some(Backend::Mock) => {}
        Some(other) => problems.push(format!("type 1 is configured as {other:?}, not mock")),
        None => problems.push("no startup line for type 1".to_owned()),
    }

    match backend(SP1_PROOF_TYPE) {
        Some(Backend::Sp1 { program_vk }) if program_vk == EXPECTED_SP1_VK => {}
        Some(other) => problems.push(format!(
            "type 2 is configured as {other:?}, not sp1 with VK {EXPECTED_SP1_VK}"
        )),
        None => problems.push("no startup line for type 2".to_owned()),
    }

    let first_publish = run.publishes.get(&1).map(|publish| publish.time);
    let before_first_publish =
        |time: DateTime<Utc>| first_publish.is_none_or(|first| time <= first);

    for role in Role::ALL {
        if !run
            .subscribed
            .get(&role)
            .is_some_and(|time| before_first_publish(*time))
        {
            problems.push(format!(
                "{role} did not see Grandine subscribe before step 1"
            ));
        }
    }

    let grandine_in_mesh = run
        .mesh_at_o
        .iter()
        .rfind(|(time, _)| before_first_publish(*time))
        .is_some_and(|(_, contains_grandine)| *contains_grandine);

    if !grandine_in_mesh {
        problems.push("Grandine is not in O's mesh before step 1".to_owned());
    }

    if !run.foreign_peers_at_o.is_empty() {
        problems.push(format!(
            "O connected to peers other than Grandine: {:?}",
            run.foreign_peers_at_o,
        ));
    }

    if problems.is_empty() {
        Cell::pass(format!(
            "type 1 mock, type 2 sp1 with VK {EXPECTED_SP1_VK}; \
             subscribed as seen by all four identities; in O's mesh",
        ))
    } else {
        Cell::inconclusive(problems.join("; "))
    }
}

fn evaluate_step(run: &Run, log: &[Line], spec: &StepSpec, observer_ready: bool) -> StepResult {
    let (grandine, at_o) = match step_context(run, spec) {
        Ok(context) => (
            evaluate_grandine(run, log, spec, &context),
            evaluate_at_o(run, log, spec, &context, observer_ready),
        ),
        Err(reason) => (
            Cell::inconclusive(reason.clone()),
            Cell::inconclusive(reason),
        ),
    };

    let sender = run.publishes.get(&spec.step).map_or_else(
        || spec.role.to_string(),
        |publish| {
            format!(
                "{}, V{} = {}",
                spec.role, spec.step, publish.key.validator_index
            )
        },
    );

    StepResult {
        step: spec.step,
        sender,
        grandine,
        at_o: Some(at_o),
    }
}

struct StepContext<'run, 'report> {
    publish: &'run Publish<'report>,
    window: &'run Window,
}

/// Finds the step's publish and window, or why the step is inconclusive.
///
/// A failed eligibility check takes precedence over every outcome.
fn step_context<'run, 'report>(
    run: &'run Run<'report>,
    spec: &StepSpec,
) -> Result<StepContext<'run, 'report>, String> {
    if let Some((stopped_step, reason)) = run.stopped
        && stopped_step < spec.step
    {
        return Err(format!(
            "not run: the run stopped at step {stopped_step} ({reason})"
        ));
    }

    if run.eligibility_failures.contains(&spec.step) {
        return Err("B's eligibility changed during the step".to_owned());
    }

    let Some(publish) = run.publishes.get(&spec.step) else {
        return Err(run.stopped.map_or_else(
            || "not published".to_owned(),
            |(stopped_step, reason)| {
                format!("not published: the run stopped at step {stopped_step} ({reason})")
            },
        ));
    };

    if let Some(error) = publish.error {
        return Err(format!("publish failed: {error}"));
    }

    let Some(window) = run.windows.get(&spec.step) else {
        return Err("the step's window was not recorded".to_owned());
    };

    // One check before publishing and one after the window.
    if run
        .eligibility_checks
        .get(&spec.step)
        .copied()
        .unwrap_or_default()
        < 2
    {
        return Err("B's eligibility was not checked before and after the step".to_owned());
    }

    Ok(StepContext { publish, window })
}

fn in_window(window: &Window, time: DateTime<Utc>) -> bool {
    window.start <= time && time <= window.end
}

fn evaluate_grandine(run: &Run, log: &[Line], spec: &StepSpec, context: &StepContext) -> Cell {
    let key = context.publish.key;
    let published = run.published_keys();

    let mut own = vec![];

    for line in log
        .iter()
        .filter(|line| in_window(context.window, line.time))
    {
        let Event::Outcome {
            key: logged,
            outcome,
        } = &line.event
        else {
            continue;
        };

        if *logged == key {
            own.push((line.time, outcome));
        } else if !published.contains(logged) {
            return Cell::fail(format!(
                "outcome {outcome:?} for {logged}, which was not published"
            ));
        }
        // An outcome for another step's message was logged late. It belongs
        // to that step, which finds no outcome in its own window.
    }

    let Some((time, outcome)) = own.first().copied() else {
        return Cell::inconclusive(format!("no outcome for {key} in the window"));
    };

    if own.iter().any(|(_, other)| *other != outcome) {
        return Cell::inconclusive(format!("conflicting outcomes for {key}"));
    }

    if let Outcome::Ignore { reason } = outcome
        && RETIREMENT_REASONS.contains(&reason.as_str())
    {
        return Cell::inconclusive(format!("IGNORE for {key} with reason {reason}"));
    }

    let logged_in_time = context
        .window
        .planned_end
        .checked_sub_signed(run.margin)
        .is_some_and(|deadline| time <= deadline);

    let cell = match (spec.expectation, outcome) {
        (Expectation::Accept, Outcome::Accept) => Cell::pass(format!("ACCEPT for {key}")),
        (Expectation::AlreadyVerified, Outcome::Ignore { reason })
            if ALREADY_VERIFIED_REASONS.contains(&reason.as_str()) =>
        {
            Cell::pass(format!("IGNORE for {key} with reason {reason}"))
        }
        (
            Expectation::RejectBinding | Expectation::RejectVerification,
            Outcome::Reject { reason },
        ) if reason == REJECT_REASON => evaluate_engine(log, spec, context, key),
        (_, outcome) => return Cell::fail(format!("{outcome:?} for {key}")),
    };

    if cell.verdict == Verdict::Pass && spec.expectation != Expectation::Accept && !logged_in_time {
        return Cell::inconclusive(format!(
            "{}, but logged less than {} s before W ended",
            cell.detail,
            run.margin.num_seconds(),
        ));
    }

    cell
}

/// Steps 3 and 4: exactly one engine line for type 2 in the window, with the
/// expected rejection.
fn evaluate_engine(log: &[Line], spec: &StepSpec, context: &StepContext, key: ProofKey) -> Cell {
    let lines = log
        .iter()
        .filter(|line| in_window(context.window, line.time))
        .filter_map(|line| match &line.event {
            Event::Engine {
                verdict,
                error,
                proof_type,
            } if *proof_type == spec.proof_type => Some((verdict.as_str(), error.as_str())),
            _ => None,
        })
        .collect::<Vec<_>>();

    let [(verdict, error)] = lines.as_slice() else {
        return Cell::inconclusive(format!(
            "REJECT for {key}, but {} engine lines for type {} in the window",
            lines.len(),
            spec.proof_type,
        ));
    };

    if *verdict == "Undetermined" {
        return Cell::inconclusive(format!(
            "REJECT for {key}, but the engine could not verify locally: {error}"
        ));
    }

    let expected = match spec.expectation {
        Expectation::RejectBinding => *error == PUBLIC_VALUES_MISMATCH,
        _ => error.starts_with(VERIFICATION_FAILURE),
    };

    if *verdict == "Invalid" && expected {
        Cell::pass(format!(
            "REJECT for {key}; engine verdict: {verdict}, {error}"
        ))
    } else {
        Cell::fail(format!(
            "REJECT for {key}, but engine verdict: {verdict}, {error}"
        ))
    }
}

fn evaluate_at_o(
    run: &Run,
    log: &[Line],
    spec: &StepSpec,
    context: &StepContext,
    observer_ready: bool,
) -> Cell {
    let publish = context.publish;

    let receipts = run
        .receipts
        .iter()
        .filter(|receipt| in_window(context.window, receipt.time))
        .filter(|receipt| {
            receipt.key == publish.key
                || receipt.ssz_sha256 == publish.ssz_sha256
                || publish.message_id == Some(receipt.message_id)
        })
        .collect::<Vec<_>>();

    if spec.expectation != Expectation::Accept {
        if let Some(receipt) = receipts.first() {
            return Cell::fail(format!(
                "received from {} at {}",
                receipt.source, receipt.time
            ));
        }

        if !observer_ready {
            return Cell::inconclusive("nothing, but step 0 did not pass");
        }

        if context.window.end < context.window.planned_end {
            return Cell::inconclusive("nothing, but the window ended early");
        }

        return Cell::pass("nothing");
    }

    if let Some(receipt) = receipts.first() {
        if receipt.source != run.grandine_peer_id {
            return Cell::inconclusive(format!("received from {}, not Grandine", receipt.source));
        }

        if receipt.ssz_sha256 != publish.ssz_sha256 {
            return Cell::fail("received from Grandine, but not byte-identical");
        }

        return Cell::pass("received from Grandine, byte-identical");
    }

    if !observer_ready {
        return Cell::inconclusive("nothing, but step 0 did not pass");
    }

    // An ACCEPT logged early enough that a forward would have reached O.
    let accepted_in_time = log.iter().any(|line| {
        matches!(
            &line.event,
            Event::Outcome { key, outcome: Outcome::Accept } if *key == publish.key
        ) && in_window(context.window, line.time)
            && context
                .window
                .planned_end
                .checked_sub_signed(run.margin)
                .is_some_and(|deadline| line.time <= deadline)
    });

    if accepted_in_time {
        Cell::fail("nothing, although Grandine ACCEPTed it")
    } else {
        Cell::inconclusive("nothing")
    }
}

#[cfg(test)]
mod tests {
    use types::phase0::primitives::H256;

    use crate::{
        report::CheckPoint,
        target::{Eligibility, Target},
    };

    use super::*;

    const GRANDINE: &str = "16Uiu2HAmGrandine";
    const OTHER_PEER: &str = "16Uiu2HAmSomeoneElse";
    const BLOCK_ROOT: H256 = H256::repeat_byte(0xbb);
    const TARGET: Target = Target {
        block_root: BLOCK_ROOT,
        slot: 40,
    };

    // W is 24 s and the margin 6 s, so an outcome must be logged by 18 s
    // after its step was published.
    const WINDOW_SECONDS: i64 = 24;

    // When each step publishes, in seconds after the run started.
    const PUBLISHED_AT: [i64; 4] = [10, 40, 70, 100];

    fn time(seconds: i64) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-30T12:00:00Z")
            .expect("the base time is valid")
            .with_timezone(&Utc)
            .checked_add_signed(TimeDelta::seconds(seconds))
            .expect("fixture times do not overflow")
    }

    fn key(step: u8) -> ProofKey {
        ProofKey {
            block_root: BLOCK_ROOT,
            proof_type: if step <= 2 {
                MOCK_PROOF_TYPE
            } else {
                SP1_PROOF_TYPE
            },
            validator_index: u64::from(step).saturating_add(10),
        }
    }

    fn published_at(step: u8) -> i64 {
        PUBLISHED_AT[usize::from(step.saturating_sub(1))]
    }

    fn role(step: u8) -> Role {
        match step {
            1 | 2 => Role::Pa,
            3 => Role::Pb,
            _ => Role::Pc,
        }
    }

    fn receipt(step: u8, seconds: i64) -> Record {
        Record::Receipt {
            time: time(seconds),
            role: Role::O,
            source: GRANDINE.to_owned(),
            message_id: format!("message {step}"),
            key: key(step),
            envelope_root: H256::repeat_byte(step),
            ssz_sha256: format!("sha256 {step}"),
        }
    }

    fn eligibility(step: u8, point: CheckPoint, seconds: i64, result: Eligibility) -> Record {
        Record::Eligibility {
            time: time(seconds),
            step,
            point,
            target: TARGET,
            result,
        }
    }

    fn clean_report() -> Vec<Record> {
        let mut records = vec![Record::RunStarted {
            time: time(0),
            grandine_peer_id: GRANDINE.to_owned(),
            chain_id: 3_151_908,
            window_ms: 24_000,
            margin_ms: 6_000,
        }];

        for role in Role::ALL {
            records.push(Record::Connection {
                time: time(1),
                role,
                peer_id: GRANDINE.to_owned(),
                connected: true,
            });
            records.push(Record::GrandineSubscribed {
                time: time(2),
                role,
            });
        }

        records.push(Record::Mesh {
            time: time(3),
            role: Role::O,
            peers: vec![GRANDINE.to_owned()],
        });

        for step in 1..=4 {
            let start = published_at(step);
            // O receives step 1 a second after it is published, which ends
            // the window. The other steps wait for all of W.
            let end = if step == 1 {
                start.saturating_add(1)
            } else {
                start.saturating_add(WINDOW_SECONDS)
            };

            records.push(eligibility(
                step,
                CheckPoint::BeforePublish,
                start,
                Eligibility::Eligible,
            ));
            records.push(Record::Publish {
                time: time(start),
                step,
                role: role(step),
                key: key(step),
                envelope_root: H256::repeat_byte(step),
                message_id: Some(format!("message {step}")),
                ssz_sha256: format!("sha256 {step}"),
                error: None,
            });

            if step == 1 {
                records.push(receipt(1, end));
            }

            records.push(Record::Window {
                step,
                start: time(start),
                planned_end: time(start.saturating_add(WINDOW_SECONDS)),
                end: time(end),
            });
            records.push(eligibility(
                step,
                CheckPoint::AfterWindow,
                end,
                Eligibility::Eligible,
            ));
        }

        records.push(Record::RunFinished { time: time(130) });
        records
    }

    fn line(seconds: i64, level: &str, target: &str, body: &str) -> String {
        format!(
            "[{}] {level} {target}: {body}",
            time(seconds).to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        )
    }

    fn identifiers(key: ProofKey) -> String {
        format!(
            "block_root: {:?}, proof_type: {}, validator_index: {}",
            key.block_root, key.proof_type, key.validator_index,
        )
    }

    fn accepted(step: u8, seconds: i64) -> String {
        line(
            seconds,
            "TRACE",
            "fork_choice_control::mutator:2815",
            &format!("execution proof accepted ({})", identifiers(key(step))),
        )
    }

    fn ignored(step: u8, seconds: i64, reason: &str) -> String {
        line(
            seconds,
            "TRACE",
            "fork_choice_control::tasks:774",
            &format!(
                "execution proof ignored ({}, outcome: IGNORE, reason: {reason})",
                identifiers(key(step)),
            ),
        )
    }

    fn rejected_with(proof_key: ProofKey, seconds: i64, reason: &str) -> String {
        line(
            seconds,
            "TRACE",
            "fork_choice_control::mutator:2821",
            &format!(
                "execution proof rejected ({}, outcome: REJECT, reason: {reason})",
                identifiers(proof_key),
            ),
        )
    }

    fn engine(seconds: i64, verdict: &str, error: &str) -> String {
        line(
            seconds,
            "DEBUG",
            "proof_engine::zkvm_engine:257",
            &format!(
                "execution proof not accepted (verdict: {verdict}, error: {error}, proof_type: 2)"
            ),
        )
    }

    struct Log {
        step_1: String,
        step_2: String,
        step_3: [String; 2],
        step_4: [String; 2],
    }

    impl Log {
        fn clean() -> Self {
            Self {
                step_1: accepted(1, 10),
                step_2: ignored(2, 41, ALREADY_VERIFIED_REASONS[0]),
                step_3: [
                    engine(75, "Invalid", PUBLIC_VALUES_MISMATCH),
                    rejected_with(key(3), 75, REJECT_REASON),
                ],
                step_4: [
                    engine(
                        105,
                        "Invalid",
                        "proof failed verification: invalid proof: public values digest mismatch",
                    ),
                    rejected_with(key(4), 105, REJECT_REASON),
                ],
            }
        }

        fn text(&self) -> String {
            [
                line(
                    0,
                    "INFO",
                    "runtime::execution_proofs:69",
                    "execution proofs of type 1 are verified with zkboost mock verification",
                ),
                line(
                    0,
                    "INFO",
                    "runtime::execution_proofs:69",
                    &format!(
                        "execution proofs of type 2 are verified with \
                         SP1 verification against verifying key {EXPECTED_SP1_VK}"
                    ),
                ),
                self.step_1.clone(),
                self.step_2.clone(),
                self.step_3.join("\n"),
                self.step_4.join("\n"),
            ]
            .join("\n")
        }
    }

    fn evaluation(records: &[Record], log: &Log) -> Evaluation {
        evaluate(records, &grandine_log::parse(&log.text()))
    }

    fn verdict(records: &[Record], log: &Log) -> Verdict {
        evaluation(records, log).verdict
    }

    fn step(evaluation: &Evaluation, step: u8) -> &StepResult {
        &evaluation.steps[usize::from(step)]
    }

    #[test]
    fn clean_run_passes() {
        let evaluation = evaluation(&clean_report(), &Log::clean());

        assert_eq!(evaluation.verdict, Verdict::Pass, "{evaluation:#?}");
        assert_eq!(evaluation.steps.len(), 5);
    }

    #[test]
    fn step_2_passes_on_either_already_verified_reason() {
        for reason in ALREADY_VERIFIED_REASONS {
            let log = Log {
                step_2: ignored(2, 41, reason),
                ..Log::clean()
            };

            assert_eq!(verdict(&clean_report(), &log), Verdict::Pass, "{reason}");
        }
    }

    #[test]
    fn forward_at_o_in_steps_2_to_4_fails() {
        for forwarded in 2..=4 {
            let mut records = clean_report();
            records.push(receipt(forwarded, published_at(forwarded) + 3));

            let evaluation = evaluation(&records, &Log::clean());

            assert_eq!(evaluation.verdict, Verdict::Fail, "step {forwarded}");
            assert_eq!(
                step(&evaluation, forwarded)
                    .at_o
                    .as_ref()
                    .map(|cell| cell.verdict),
                Some(Verdict::Fail),
            );
        }
    }

    #[test]
    fn outcome_for_the_wrong_key_fails() {
        let wrong_keys = [
            ProofKey {
                validator_index: 99,
                ..key(3)
            },
            ProofKey {
                block_root: H256::repeat_byte(0xcc),
                ..key(3)
            },
        ];

        for wrong_key in wrong_keys {
            let log = Log {
                step_3: [
                    engine(75, "Invalid", PUBLIC_VALUES_MISMATCH),
                    rejected_with(wrong_key, 75, REJECT_REASON),
                ],
                ..Log::clean()
            };

            let evaluation = evaluation(&clean_report(), &log);

            assert_eq!(evaluation.verdict, Verdict::Fail, "{wrong_key}");
            assert_eq!(step(&evaluation, 3).grandine.verdict, Verdict::Fail);
        }
    }

    #[test]
    fn step_2_fails_on_any_other_ignore_reason() {
        let reasons = [
            "execution proof has already been processed",
            "proof already seen from this prover for this beacon block and proof type",
            "execution proof's beacon block has not been seen",
            "SeenRoot",
            "already verified",
        ];

        for reason in reasons {
            let log = Log {
                step_2: ignored(2, 41, reason),
                ..Log::clean()
            };

            assert_eq!(verdict(&clean_report(), &log), Verdict::Fail, "{reason}");
        }
    }

    #[test]
    fn reject_with_another_reason_in_steps_3_and_4_fails() {
        let log = Log {
            step_3: [
                engine(75, "Invalid", PUBLIC_VALUES_MISMATCH),
                rejected_with(key(3), 75, "invalid signature"),
            ],
            ..Log::clean()
        };

        assert_eq!(verdict(&clean_report(), &log), Verdict::Fail);

        let log = Log {
            step_4: [
                engine(105, "Invalid", "proof failed verification: bad proof"),
                rejected_with(key(4), 105, "invalid signature"),
            ],
            ..Log::clean()
        };

        assert_eq!(verdict(&clean_report(), &log), Verdict::Fail);
    }

    #[test]
    fn wrong_engine_rejection_fails() {
        // The genuine fixture failing SP1 verification contradicts goal 2.
        let log = Log {
            step_3: [
                engine(75, "Invalid", "proof failed verification: bad proof"),
                rejected_with(key(3), 75, REJECT_REASON),
            ],
            ..Log::clean()
        };

        assert_eq!(verdict(&clean_report(), &log), Verdict::Fail);
    }

    #[test]
    fn missing_outcome_is_inconclusive() {
        let log = Log {
            step_1: String::new(),
            ..Log::clean()
        };

        let evaluation = evaluation(&clean_report(), &log);

        assert_eq!(evaluation.verdict, Verdict::Inconclusive);
        assert_eq!(step(&evaluation, 1).grandine.verdict, Verdict::Inconclusive);
    }

    #[test]
    fn missing_engine_line_is_inconclusive() {
        let log = Log {
            step_4: [String::new(), rejected_with(key(4), 105, REJECT_REASON)],
            ..Log::clean()
        };

        assert_eq!(verdict(&clean_report(), &log), Verdict::Inconclusive);
    }

    #[test]
    fn outcome_logged_less_than_the_margin_before_w_ends_is_inconclusive() {
        // Step 2 is published at 40 s, so its outcome is due by 58 s.
        let log = Log {
            step_2: ignored(2, 59, ALREADY_VERIFIED_REASONS[0]),
            ..Log::clean()
        };

        assert_eq!(verdict(&clean_report(), &log), Verdict::Inconclusive);

        let log = Log {
            step_2: ignored(2, 58, ALREADY_VERIFIED_REASONS[0]),
            ..Log::clean()
        };

        assert_eq!(verdict(&clean_report(), &log), Verdict::Pass);
    }

    #[test]
    fn second_peer_at_o_is_inconclusive() {
        let mut records = clean_report();
        records.insert(
            1,
            Record::Connection {
                time: time(1),
                role: Role::O,
                peer_id: OTHER_PEER.to_owned(),
                connected: true,
            },
        );

        let evaluation = evaluation(&records, &Log::clean());

        assert_eq!(evaluation.verdict, Verdict::Inconclusive);
        assert_eq!(step(&evaluation, 0).grandine.verdict, Verdict::Inconclusive);
    }

    #[test]
    fn retirement_reasons_are_inconclusive() {
        for reason in RETIREMENT_REASONS {
            let log = Log {
                step_2: ignored(2, 41, reason),
                ..Log::clean()
            };

            assert_eq!(
                verdict(&clean_report(), &log),
                Verdict::Inconclusive,
                "{reason}"
            );

            // Also where a REJECT is expected: a retired B is never a failure.
            let log = Log {
                step_3: [String::new(), ignored(3, 75, reason)],
                ..Log::clean()
            };

            assert_eq!(
                verdict(&clean_report(), &log),
                Verdict::Inconclusive,
                "{reason}"
            );
        }
    }

    #[test]
    fn failed_eligibility_check_is_inconclusive_whatever_the_reason() {
        let failures = [
            Eligibility::SlotEmpty,
            Eligibility::Finalized,
            Eligibility::FinalityUnknown,
            Eligibility::NotCanonical {
                returned_root: H256::repeat_byte(0xcc),
            },
        ];

        for failure in failures {
            let mut records = clean_report();

            for record in &mut records {
                if let Record::Eligibility {
                    step: 2,
                    point: CheckPoint::AfterWindow,
                    result,
                    ..
                } = record
                {
                    *result = failure;
                }
            }

            // An orphaned B that finalization pruned reaches precheck as an
            // unseen block, which would otherwise fail step 2.
            let log = Log {
                step_2: ignored(2, 41, "execution proof's beacon block has not been seen"),
                ..Log::clean()
            };

            let evaluation = evaluation(&records, &log);

            assert_eq!(evaluation.verdict, Verdict::Inconclusive, "{failure:?}");
            assert_eq!(step(&evaluation, 2).grandine.verdict, Verdict::Inconclusive);
        }
    }

    #[test]
    fn steps_after_a_stop_are_inconclusive() {
        let mut records = clean_report();
        records.retain(|record| {
            !matches!(
                record,
                Record::Publish { step: 3 | 4, .. }
                    | Record::Window { step: 3 | 4, .. }
                    | Record::Eligibility { step: 3 | 4, .. }
            )
        });
        records.push(Record::Stopped {
            time: time(65),
            step: 3,
            reason: "B's eligibility changed before publishing".to_owned(),
        });

        let evaluation = evaluation(&records, &Log::clean());

        assert_eq!(evaluation.verdict, Verdict::Inconclusive);
        assert_eq!(step(&evaluation, 2).grandine.verdict, Verdict::Pass);
        assert_eq!(step(&evaluation, 3).grandine.verdict, Verdict::Inconclusive);
    }

    #[test]
    fn step_1_without_a_receipt_after_accept_fails() {
        let mut records = clean_report();
        records.retain(|record| !matches!(record, Record::Receipt { .. }));

        for record in &mut records {
            if let Record::Window { step: 1, end, .. } = record {
                *end = time(10 + WINDOW_SECONDS);
            }
        }

        let evaluation = evaluation(&records, &Log::clean());

        assert_eq!(evaluation.verdict, Verdict::Fail);
        assert_eq!(
            step(&evaluation, 1).at_o.as_ref().map(|cell| cell.verdict),
            Some(Verdict::Fail),
        );
    }

    #[test]
    fn step_1_receipt_that_differs_fails() {
        let mut records = clean_report();

        for record in &mut records {
            if let Record::Receipt { ssz_sha256, .. } = record {
                *ssz_sha256 = "different".to_owned();
            }
        }

        assert_eq!(verdict(&records, &Log::clean()), Verdict::Fail);
    }

    #[test]
    fn empty_report_is_inconclusive() {
        assert_eq!(verdict(&[], &Log::clean()), Verdict::Inconclusive);
    }

    #[test]
    fn wrong_startup_configuration_is_inconclusive() {
        let log = Log::clean();
        let text = log
            .text()
            .replace(EXPECTED_SP1_VK, &format!("0x{}", "11".repeat(32)));
        let evaluation = evaluate(&clean_report(), &grandine_log::parse(&text));

        assert_eq!(evaluation.verdict, Verdict::Inconclusive);
        assert_eq!(step(&evaluation, 0).grandine.verdict, Verdict::Inconclusive);
    }
}
