//! Runs the steps of design 0012 against a live devnet and writes the report.
//!
//! The run never decides pass or fail. It records what it published, what
//! the identities observed and each check of B's eligibility. It stops early,
//! before publishing the next step, when B's eligibility changes or Grandine
//! reports `Retired` or `ContextInapplicable` for the step's message.

use core::{marker::PhantomData, time::Duration};
use std::{
    collections::BTreeSet,
    io::{Read as _, Seek as _, SeekFrom},
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, anyhow, ensure};
use bls::SecretKey;
use chrono::{TimeDelta, Utc};
use clap::Args;
use eth2_libp2p::{
    Multiaddr, PeerId,
    multiaddr::Protocol,
    rpc::{StatusMessage, StatusMessageV2},
    types::ForkContext,
};
use fs_err::File;
use ssz::{SszHash as _, SszWrite as _};
use tokio::sync::mpsc;
use tracing::info;
use types::{
    config::Config,
    eip8025::containers::{ExecutionProofEnvelope, SignedExecutionProofEnvelope},
    nonstandard::{ForkInfo, Phase},
    phase0::{
        consts::GENESIS_EPOCH,
        primitives::{H256, Slot, UnixSeconds, ValidatorIndex},
    },
    preset::Preset,
    redacting_url::RedactingUrl,
};

use crate::{
    beacon::{BeaconClient, Genesis},
    chain,
    evaluate::RETIREMENT_REASONS,
    grandine_log::{self, Event, Outcome},
    identity::{self, IdentityConfig, IdentityEvent, IdentityHandle, TimedEvent},
    keys::{self, KeystoreFile},
    messages::{self, MOCK_PROOF_TYPE, SP1_PROOF_TYPE, STEP_1_MOCK_PROOF, STEP_2_MOCK_PROOF},
    report::{CheckPoint, ProofKey, Record, ReportWriter, Role},
    target::{self, LiveChain, Target},
    verdict::Verdict,
};

const TARGET_POLL_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Args)]
pub struct RunArgs {
    /// Grandine's Beacon API.
    #[clap(long)]
    beacon_url: RedactingUrl,
    /// The enclave's `config.yaml`, from the genesis artifact.
    #[clap(long)]
    config: PathBuf,
    /// The participant's keystores (`teku-keys`).
    #[clap(long)]
    keystore_dir: PathBuf,
    /// The participant's keystore passwords (`teku-secrets`).
    #[clap(long)]
    password_dir: PathBuf,
    /// Where to write the JSONL report.
    #[clap(long)]
    report: PathBuf,
    /// Grandine's log while it is being written. With it, the run stops when
    /// Grandine reports that B retired.
    #[clap(long)]
    grandine_log: Option<PathBuf>,
    /// Grandine's libp2p address. Defaults to the TCP address in
    /// `/eth/v1/node/identity`.
    #[clap(long)]
    grandine_address: Option<Multiaddr>,
    /// W, in slots.
    #[clap(long, default_value_t = 2)]
    window_slots: u32,
    /// How long before W ends Grandine's outcome must be logged.
    #[clap(long, default_value_t = 6)]
    margin_secs: u64,
    /// How long to wait for the identities to see Grandine subscribed.
    #[clap(long, default_value_t = 120)]
    setup_timeout_secs: u64,
    /// How long to wait for Grandine to stop syncing with a Gloas head and
    /// a candidate B.
    #[clap(long, default_value_t = 600)]
    target_timeout_secs: u64,
}

struct Clock {
    genesis_time: UnixSeconds,
    slot_duration: Duration,
}

impl Clock {
    fn current_slot(&self) -> Result<Slot> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let since_genesis = now.saturating_sub(Duration::from_secs(self.genesis_time));
        let slot_ms = self.slot_duration.as_millis();

        let slot = since_genesis
            .as_millis()
            .checked_div(slot_ms)
            .ok_or_else(|| anyhow!("the slot duration is zero"))?;

        Ok(Slot::try_from(slot)?)
    }
}

/// One step's message and who sends it.
struct Step {
    number: u8,
    role: Role,
    message: Arc<SignedExecutionProofEnvelope>,
}

impl Step {
    fn key(&self) -> ProofKey {
        ProofKey {
            block_root: self.message.message.beacon_block_root,
            proof_type: self.message.message.proof_type,
            validator_index: self.message.validator_index,
        }
    }
}

pub async fn run<P: Preset>(args: RunArgs) -> Result<Verdict> {
    let config = Arc::new(chain::load_config(&args.config)?);
    let client = BeaconClient::new(args.beacon_url.clone())?;
    let live_chain = LiveChain::<P> {
        client: &client,
        phantom: PhantomData,
    };

    let target_timeout = Duration::from_secs(args.target_timeout_secs);
    let node = wait_for_node(&client, args.grandine_address.clone(), target_timeout).await?;
    let Node {
        genesis,
        peer_id: grandine_peer_id,
        address: grandine_address,
    } = node;

    let clock = Clock {
        genesis_time: genesis.genesis_time,
        slot_duration: config.slot_duration_ms,
    };

    let window = config
        .slot_duration_ms
        .checked_mul(args.window_slots)
        .context("W overflows")?;
    let margin = Duration::from_secs(args.margin_secs);

    let mut report = ReportWriter::create(&args.report)?;

    report.write(&Record::RunStarted {
        time: Utc::now(),
        grandine_peer_id: grandine_peer_id.to_string(),
        chain_id: config.deposit_chain_id,
        window_ms: u64::try_from(window.as_millis())?,
        margin_ms: u64::try_from(margin.as_millis())?,
    })?;

    // B.
    let Some(target) = wait_for_target::<P>(&config, &live_chain, &clock, target_timeout).await?
    else {
        return stop(
            &mut report,
            0,
            "Grandine did not stop syncing with a Gloas head and a candidate B in time",
        );
    };

    info!(?target, "selected B");
    report.write(&Record::Target {
        time: Utc::now(),
        target,
    })?;

    // The four messages.
    let keystores = keys::discover(&args.keystore_dir, &args.password_dir)?;
    let validators = select_validators(&client, &keystores, target.slot).await?;
    let steps = build_steps::<P>(
        &client,
        &config,
        &genesis.genesis_validators_root,
        target,
        &validators,
    )
    .await?;

    // The identities.
    let identity_config = identity_config::<P>(
        &client,
        Arc::clone(&config),
        clock.current_slot()?,
        &genesis,
        grandine_peer_id,
        grandine_address,
    )
    .await?;

    let setup_deadline = tokio::time::Instant::now()
        .checked_add(Duration::from_secs(args.setup_timeout_secs))
        .context("setup timeout overflows")?;

    let publication = Publication {
        live_chain: &live_chain,
        target,
        window,
        setup_deadline,
        log_follower: args.grandine_log.clone().map(LogFollower::new),
    };

    publication.publish(report, &identity_config, &steps).await
}

/// What the publishing half of a run needs once B and the messages are fixed.
struct Publication<'chain, P> {
    live_chain: &'chain LiveChain<'chain, P>,
    target: Target,
    window: Duration,
    setup_deadline: tokio::time::Instant,
    log_follower: Option<LogFollower>,
}

impl<P: Preset> Publication<'_, P> {
    /// Starts the identities, waits for step 0's condition and runs the
    /// steps in order.
    async fn publish(
        mut self,
        report: ReportWriter,
        identity_config: &IdentityConfig,
        steps: &[Step],
    ) -> Result<Verdict> {
        let (event_sender, events) = mpsc::unbounded_channel();
        let mut hub = Hub::new(events, report, identity_config.grandine_peer_id);

        let Some(handles) = spawn_identities::<P>(
            &mut hub,
            identity_config,
            &event_sender,
            self.setup_deadline,
        )
        .await?
        else {
            return stop(
                &mut hub.report,
                0,
                "an identity did not connect to Grandine",
            );
        };

        // Step 0: wait until every identity sees Grandine subscribed and O has
        // it in its mesh. The evaluator checks R1's startup lines.
        if !hub
            .wait_until(self.setup_deadline, Observed::is_ready)
            .await?
        {
            return stop(
                &mut hub.report,
                0,
                "the identities did not all see Grandine subscribed, with Grandine in O's mesh",
            );
        }

        for step in steps {
            let handle = handles
                .iter()
                .find(|handle| handle.role() == step.role)
                .context("every role has an identity")?;

            if let Some(reason) = run_step(
                &mut hub,
                self.live_chain,
                self.target,
                step,
                handle,
                self.window,
                self.log_follower.as_mut(),
            )
            .await?
            {
                return stop(&mut hub.report, step.number, &reason);
            }
        }

        hub.drain()?;
        hub.report
            .write(&Record::RunFinished { time: Utc::now() })?;

        Ok(Verdict::Pass)
    }
}

/// Starts the four identities. Returns `None` if one did not connect to
/// Grandine before the setup deadline.
async fn spawn_identities<P: Preset>(
    hub: &mut Hub,
    identity_config: &IdentityConfig,
    event_sender: &mpsc::UnboundedSender<TimedEvent>,
    setup_deadline: tokio::time::Instant,
) -> Result<Option<Vec<IdentityHandle>>> {
    let mut handles = vec![];

    // `eth2_libp2p` admits at most two pending connections from one IP, so
    // each identity connects before the next starts.
    for role in Role::ALL {
        let handle = identity::spawn::<P>(role, identity_config, event_sender.clone()).await?;

        hub.report.write(&Record::Identity {
            time: Utc::now(),
            role,
            peer_id: handle.peer_id().to_string(),
        })?;

        if !hub
            .wait_until(setup_deadline, |observed| {
                observed.connected.contains(&role)
            })
            .await?
        {
            return Ok(None);
        }

        handles.push(handle);
    }

    Ok(Some(handles))
}

/// Runs one step. Returns why the run must stop, if it must.
async fn run_step<P: Preset>(
    hub: &mut Hub,
    live_chain: &LiveChain<'_, P>,
    target: Target,
    step: &Step,
    handle: &IdentityHandle,
    window: Duration,
    log_follower: Option<&mut LogFollower>,
) -> Result<Option<String>> {
    if !check_eligibility(
        hub,
        live_chain,
        target,
        step.number,
        CheckPoint::BeforePublish,
    )
    .await?
    {
        return Ok(Some("B's eligibility changed before publishing".to_owned()));
    }

    let start = Utc::now();
    let window_deadline = tokio::time::Instant::now()
        .checked_add(window)
        .context("W overflows")?;
    let result = handle.publish(Arc::clone(&step.message)).await;

    hub.report.write(&Record::Publish {
        time: start,
        step: step.number,
        role: step.role,
        key: step.key(),
        envelope_root: step.message.message.hash_tree_root(),
        message_id: result.as_ref().ok().map(ToString::to_string),
        ssz_sha256: identity::sha256_hex(&step.message.to_ssz()?),
        error: result.as_ref().err().map(|error| format!("{error:#}")),
    })?;

    let message_id = match result {
        Ok(message_id) => message_id.to_string(),
        Err(error) => {
            return Ok(Some(format!(
                "publishing step {} failed: {error:#}",
                step.number
            )));
        }
    };

    info!(step = step.number, %message_id, "published");

    // Wait for O to receive the message or for W to end.
    hub.wait_until(window_deadline, |observed| {
        observed.received.contains(&message_id)
    })
    .await?;

    hub.report.write(&Record::Window {
        step: step.number,
        start,
        planned_end: start
            .checked_add_signed(TimeDelta::from_std(window)?)
            .context("W overflows")?,
        end: Utc::now(),
    })?;

    if !check_eligibility(
        hub,
        live_chain,
        target,
        step.number,
        CheckPoint::AfterWindow,
    )
    .await?
    {
        return Ok(Some("B's eligibility changed during the window".to_owned()));
    }

    if let Some(follower) = log_follower {
        let key = step.key();

        let retired = follower
            .read_new_lines()?
            .into_iter()
            .find_map(|line| match line.event {
                Event::Outcome {
                    key: logged,
                    outcome: Outcome::Ignore { reason },
                } if logged == key && RETIREMENT_REASONS.contains(&reason.as_str()) => Some(reason),
                _ => None,
            });

        if let Some(reason) = retired {
            return Ok(Some(format!("Grandine reported {reason} for {key}")));
        }
    }

    Ok(None)
}

async fn check_eligibility<P: Preset>(
    hub: &mut Hub,
    live_chain: &LiveChain<'_, P>,
    target: Target,
    step: u8,
    point: CheckPoint,
) -> Result<bool> {
    let result = target::check(live_chain, target).await?;

    hub.report.write(&Record::Eligibility {
        time: Utc::now(),
        step,
        point,
        target,
        result,
    })?;

    Ok(result.is_eligible())
}

fn stop(report: &mut ReportWriter, step: u8, reason: &str) -> Result<Verdict> {
    tracing::warn!(step, reason, "run stopped");

    report.write(&Record::Stopped {
        time: Utc::now(),
        step,
        reason: reason.to_owned(),
    })?;

    report.write(&Record::RunFinished { time: Utc::now() })?;

    Ok(Verdict::Inconclusive)
}

struct Node {
    genesis: Genesis,
    peer_id: PeerId,
    address: Multiaddr,
}

/// Waits for Grandine's Beacon API and reads what the identities need.
async fn wait_for_node(
    client: &BeaconClient,
    address: Option<Multiaddr>,
    timeout: Duration,
) -> Result<Node> {
    let deadline = tokio::time::Instant::now()
        .checked_add(timeout)
        .context("target timeout overflows")?;

    let (genesis, identity) = loop {
        match futures::try_join!(client.genesis(), client.identity()) {
            Ok(responses) => break responses,
            Err(error) if tokio::time::Instant::now() < deadline => {
                tracing::debug!(?error, "Grandine's Beacon API is not ready");
                tokio::time::sleep(TARGET_POLL_INTERVAL).await;
            }
            Err(error) => return Err(error.context("Grandine's Beacon API did not answer")),
        }
    };

    let address = match address {
        Some(address) => address,
        None => tcp_address(&identity.p2p_addresses)
            .context("Grandine reports no TCP address; pass --grandine-address")?,
    };

    Ok(Node {
        genesis,
        peer_id: identity.peer_id.parse()?,
        address,
    })
}

async fn wait_for_target<P: Preset>(
    config: &Config,
    live_chain: &LiveChain<'_, P>,
    clock: &Clock,
    timeout: Duration,
) -> Result<Option<Target>> {
    let deadline = tokio::time::Instant::now()
        .checked_add(timeout)
        .context("target timeout overflows")?;

    loop {
        // The node may not be serving its API yet.
        match ready_for_target::<P>(config, live_chain, clock).await {
            Ok(Some(target)) => return Ok(Some(target)),
            Ok(None) => {}
            Err(error) => tracing::debug!(?error, "Grandine is not ready"),
        }

        if tokio::time::Instant::now() >= deadline {
            return Ok(None);
        }

        tokio::time::sleep(TARGET_POLL_INTERVAL).await;
    }
}

async fn ready_for_target<P: Preset>(
    config: &Config,
    live_chain: &LiveChain<'_, P>,
    clock: &Clock,
) -> Result<Option<Target>> {
    if live_chain.client.syncing().await?.is_syncing {
        return Ok(None);
    }

    let head = live_chain.client.head_header().await?;

    if config.phase_at_slot::<P>(head.slot) < Phase::Gloas {
        return Ok(None);
    }

    target::select::<P>(live_chain, clock.current_slot()?).await
}

/// Picks the first four keystores whose validators are active at B's state.
async fn select_validators(
    client: &BeaconClient,
    keystores: &[KeystoreFile],
    slot: Slot,
) -> Result<Vec<(ValidatorIndex, SecretKey)>> {
    let mut selected = vec![];

    for keystore in keystores {
        if selected.len() == Role::ALL.len() {
            break;
        }

        let Some(validator) = client
            .validator(slot, &format!("{:?}", keystore.pubkey()))
            .await?
        else {
            continue;
        };

        if validator.is_active() {
            selected.push((validator.index, keystore.decrypt()?));
        }
    }

    ensure!(
        selected.len() == Role::ALL.len(),
        "found {} active validators among {} keystores; four are needed",
        selected.len(),
        keystores.len(),
    );

    Ok(selected)
}

async fn build_steps<P: Preset>(
    client: &BeaconClient,
    config: &Config,
    genesis_validators_root: &H256,
    target: Target,
    validators: &[(ValidatorIndex, SecretKey)],
) -> Result<Vec<Step>> {
    let envelope = client
        .envelope::<P>(target.block_root)
        .await?
        .context("B's envelope is no longer returned")?;

    ensure!(
        envelope.execution_optimistic == Some(false),
        "B's envelope is optimistic",
    );
    ensure!(
        envelope.envelope.message.beacon_block_root == target.block_root,
        "B's envelope is for another block",
    );

    let bid = client.bid::<P>(target.block_root).await?;

    ensure!(
        bid.message.slot == target.slot,
        "the bid in B is for slot {}, not {}",
        bid.message.slot,
        target.slot,
    );

    let public_input = messages::public_input(config, &envelope.envelope.message, &bid.message)?;

    // Grandine verifies against B's post-state, whose slot is B's.
    let fork_info = ForkInfo {
        fork: client.fork(target.slot).await?,
        genesis_validators_root: *genesis_validators_root,
    };

    let unsigned: [(u8, Role, ExecutionProofEnvelope); 4] = [
        (
            1,
            Role::Pa,
            messages::envelope(
                messages::mock_proof_data(public_input, STEP_1_MOCK_PROOF)?,
                MOCK_PROOF_TYPE,
                target.block_root,
            ),
        ),
        (
            2,
            Role::Pa,
            messages::envelope(
                messages::mock_proof_data(public_input, STEP_2_MOCK_PROOF)?,
                MOCK_PROOF_TYPE,
                target.block_root,
            ),
        ),
        (
            3,
            Role::Pb,
            messages::envelope(
                messages::sp1_proof_data()?,
                SP1_PROOF_TYPE,
                target.block_root,
            ),
        ),
        (
            4,
            Role::Pc,
            messages::envelope(
                messages::tampered_sp1_proof_data()?,
                SP1_PROOF_TYPE,
                target.block_root,
            ),
        ),
    ];

    Ok(unsigned
        .into_iter()
        .zip(validators)
        .map(
            |((number, role, envelope), (validator_index, secret_key))| Step {
                number,
                role,
                message: Arc::new(messages::sign::<P>(
                    config,
                    fork_info,
                    target.slot,
                    envelope,
                    *validator_index,
                    secret_key,
                )),
            },
        )
        .collect())
}

async fn identity_config<P: Preset>(
    client: &BeaconClient,
    config: Arc<Config>,
    current_slot: Slot,
    genesis: &Genesis,
    grandine_peer_id: PeerId,
    grandine_address: Multiaddr,
) -> Result<IdentityConfig> {
    let fork_context = Arc::new(ForkContext::new::<P>(
        &config,
        current_slot,
        genesis.genesis_validators_root,
    ));

    Ok(IdentityConfig {
        current_phase: config.phase_at_slot::<P>(current_slot),
        status: status(client, &fork_context).await?,
        chain_config: config,
        fork_context,
        grandine_peer_id,
        grandine_address,
    })
}

/// The Status each identity sends, built from Grandine's Beacon API as
/// Grandine builds its own.
async fn status(client: &BeaconClient, fork_context: &ForkContext) -> Result<StatusMessage> {
    let head = client.head_header().await?;
    let finalized = client.finalized_checkpoint().await?;

    let finalized_root = if finalized.epoch == GENESIS_EPOCH {
        H256::zero()
    } else {
        finalized.root
    };

    Ok(StatusMessage::V2(StatusMessageV2 {
        fork_digest: fork_context.current_fork_digest(),
        finalized_root,
        finalized_epoch: finalized.epoch,
        head_root: head.root,
        head_slot: head.slot,
        // The identities serve no chain data.
        earliest_available_slot: head.slot,
    }))
}

fn tcp_address(addresses: &[Multiaddr]) -> Option<Multiaddr> {
    addresses
        .iter()
        .find(|address| {
            address
                .iter()
                .any(|protocol| matches!(protocol, Protocol::Tcp(_)))
        })
        .map(|address| {
            address
                .iter()
                .filter(|protocol| !matches!(protocol, Protocol::P2p(_)))
                .collect()
        })
}

/// What the identities have observed so far.
#[derive(Default)]
struct Observed {
    connected: BTreeSet<Role>,
    subscribed: BTreeSet<Role>,
    grandine_in_mesh: bool,
    received: BTreeSet<String>,
}

impl Observed {
    fn is_ready(&self) -> bool {
        self.subscribed.len() == Role::ALL.len() && self.grandine_in_mesh
    }
}

/// Records identity events in the report as they arrive.
struct Hub {
    events: mpsc::UnboundedReceiver<TimedEvent>,
    report: ReportWriter,
    grandine_peer_id: PeerId,
    observed: Observed,
}

impl Hub {
    fn new(
        events: mpsc::UnboundedReceiver<TimedEvent>,
        report: ReportWriter,
        grandine_peer_id: PeerId,
    ) -> Self {
        Self {
            events,
            report,
            grandine_peer_id,
            observed: Observed::default(),
        }
    }

    async fn wait_until(
        &mut self,
        deadline: tokio::time::Instant,
        condition: impl Fn(&Observed) -> bool,
    ) -> Result<bool> {
        loop {
            if condition(&self.observed) {
                return Ok(true);
            }

            tokio::select! {
                event = self.events.recv() => match event {
                    Some(event) => self.handle(event)?,
                    None => return Ok(false),
                },
                () = tokio::time::sleep_until(deadline) => return Ok(condition(&self.observed)),
            }
        }
    }

    /// Records the events that have already arrived.
    fn drain(&mut self) -> Result<()> {
        while let Ok(event) = self.events.try_recv() {
            self.handle(event)?;
        }

        Ok(())
    }

    fn handle(&mut self, event: TimedEvent) -> Result<()> {
        let TimedEvent { time, role, event } = event;

        let record = match event {
            IdentityEvent::Connection { peer_id, connected } => {
                if peer_id == self.grandine_peer_id {
                    if connected {
                        self.observed.connected.insert(role);
                    } else {
                        self.observed.connected.remove(&role);
                    }
                }

                Record::Connection {
                    time,
                    role,
                    peer_id: peer_id.to_string(),
                    connected,
                }
            }
            IdentityEvent::GrandineSubscribed => {
                self.observed.subscribed.insert(role);
                Record::GrandineSubscribed { time, role }
            }
            IdentityEvent::Mesh { peers } => {
                if role == Role::O {
                    self.observed.grandine_in_mesh = peers.contains(&self.grandine_peer_id);
                }

                Record::Mesh {
                    time,
                    role,
                    peers: peers.iter().map(ToString::to_string).collect(),
                }
            }
            IdentityEvent::Receipt {
                source,
                message_id,
                key,
                envelope_root,
                ssz_sha256,
            } => {
                if role == Role::O {
                    self.observed.received.insert(message_id.to_string());
                }

                Record::Receipt {
                    time,
                    role,
                    source: source.to_string(),
                    message_id: message_id.to_string(),
                    key,
                    envelope_root,
                    ssz_sha256,
                }
            }
        };

        self.report.write(&record)
    }
}

/// Reads the lines appended to Grandine's log since the last read.
struct LogFollower {
    path: PathBuf,
    offset: u64,
    partial: String,
}

impl LogFollower {
    const fn new(path: PathBuf) -> Self {
        Self {
            path,
            offset: 0,
            partial: String::new(),
        }
    }

    fn read_new_lines(&mut self) -> Result<Vec<grandine_log::Line>> {
        let mut file = File::open(&self.path)?;
        file.seek(SeekFrom::Start(self.offset))?;

        let mut bytes = vec![];
        let read = file.read_to_end(&mut bytes)?;
        self.offset = self.offset.saturating_add(u64::try_from(read)?);

        self.partial.push_str(&String::from_utf8_lossy(&bytes));

        let complete_up_to = self
            .partial
            .rfind('\n')
            .map_or(0, |index| index.saturating_add(1));
        let complete = self.partial.drain(..complete_up_to).collect::<String>();

        Ok(grandine_log::parse(&complete))
    }
}
