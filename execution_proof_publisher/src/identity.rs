//! One `eth2_libp2p` instance with its own key.
//!
//! Each identity dials Grandine and nothing else, and redials while it is
//! not connected. `eth2_libp2p` admits at most two pending connections from
//! one IP, and all four identities share one, so the run starts them one at
//! a time. It sends Status built from
//! Grandine's Beacon API, because Grandine sends Status only on its own
//! outgoing connections. It answers later Status requests with the request's
//! own Status and every block, blob, column, envelope and light-client
//! request with `ResourceUnavailable`. `eth2_libp2p` answers `Ping` and
//! `MetaData`. Every message it receives is reported as IGNORE, so no identity
//! re-forwards.

use core::{net::Ipv4Addr, time::Duration};
use std::{collections::BTreeSet, sync::Arc};

use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use eth2_libp2p::{
    Context, MessageAcceptance, MessageId, Multiaddr, NetworkConfig, NetworkEvent, PeerId,
    PubsubMessage, Response, TaskExecutor, Topic, TopicHash,
    libp2p::identity::{Keypair, secp256k1},
    rpc::{
        RequestType, StatusMessage,
        methods::{RpcErrorResponse, RpcResponse},
    },
    service::{Network, api_types::AppRequestId},
    types::{EnrForkId, ForkContext, GossipEncoding, GossipKind, GossipTopic},
};
use futures::channel::mpsc;
use ssz::{SszHash as _, SszWrite as _};
use tokio::{
    sync::{mpsc as tokio_mpsc, oneshot},
    time::{Instant, MissedTickBehavior},
};
use types::{
    config::Config,
    eip8025::containers::SignedExecutionProofEnvelope,
    nonstandard::Phase,
    phase0::{consts::FAR_FUTURE_EPOCH, primitives::H256},
    preset::Preset,
};

use crate::report::{ProofKey, Role};

const STATE_POLL_INTERVAL: Duration = Duration::from_millis(250);
const REDIAL_INTERVAL: Duration = Duration::from_secs(5);

/// What an identity reports to the run.
pub enum IdentityEvent {
    Connection {
        peer_id: PeerId,
        connected: bool,
    },
    GrandineSubscribed,
    Mesh {
        peers: Vec<PeerId>,
    },
    Receipt {
        source: PeerId,
        message_id: MessageId,
        key: ProofKey,
        envelope_root: H256,
        ssz_sha256: String,
    },
}

pub struct TimedEvent {
    pub time: DateTime<Utc>,
    pub role: Role,
    pub event: IdentityEvent,
}

enum Command {
    Publish {
        message: Arc<SignedExecutionProofEnvelope>,
        reply: oneshot::Sender<Result<MessageId>>,
    },
}

/// The handle the run uses to drive one identity.
pub struct IdentityHandle {
    role: Role,
    peer_id: PeerId,
    commands: tokio_mpsc::UnboundedSender<Command>,
}

impl IdentityHandle {
    pub const fn role(&self) -> Role {
        self.role
    }

    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Publishes a message and returns its gossipsub message ID.
    pub async fn publish(&self, message: Arc<SignedExecutionProofEnvelope>) -> Result<MessageId> {
        let (reply, receiver) = oneshot::channel();

        self.commands
            .send(Command::Publish { message, reply })
            .map_err(|_| anyhow!("identity {} has stopped", self.role))?;

        receiver.await?
    }
}

pub struct IdentityConfig {
    pub chain_config: Arc<Config>,
    pub fork_context: Arc<ForkContext>,
    pub grandine_peer_id: PeerId,
    pub grandine_address: Multiaddr,
    pub current_phase: Phase,
    pub status: StatusMessage,
}

impl IdentityConfig {
    fn topic(&self) -> GossipTopic {
        GossipTopic::new(
            GossipKind::ExecutionProof,
            GossipEncoding::default(),
            self.fork_context.current_fork_digest(),
        )
    }
}

/// Starts an identity with a fresh key and returns its handle.
pub async fn spawn<P: Preset>(
    role: Role,
    config: &IdentityConfig,
    events: tokio_mpsc::UnboundedSender<TimedEvent>,
) -> Result<IdentityHandle> {
    let chain_config = Arc::clone(&config.chain_config);

    let mut network_config = NetworkConfig::default();

    // Grandine is the only peer. It is dialled directly, never discovered.
    network_config.set_ipv4_listening_address(Ipv4Addr::UNSPECIFIED, 0, 0, 0);
    network_config.network_dir = None;
    network_config.disable_discovery = true;
    network_config.disable_quic_support = true;
    network_config.upnp_enabled = false;
    network_config.boot_nodes_multiaddr = vec![config.grandine_address.clone()];
    network_config.enable_execution_proof = true;

    let context = Context {
        chain_config: Arc::clone(&chain_config),
        config: Arc::new(network_config),
        // Nothing reads the ENR: discovery is off and Grandine is dialled directly.
        enr_fork_id: EnrForkId {
            fork_digest: config.fork_context.current_fork_digest(),
            next_fork_version: chain_config.version(config.current_phase),
            next_fork_epoch: FAR_FUTURE_EPOCH,
        },
        fork_context: Arc::clone(&config.fork_context),
        libp2p_registry: None,
    };

    // The executor's shutdown signal is never acted on: the run owns the process.
    let (shutdown_tx, _) = mpsc::channel(1);
    let keypair: Keypair = secp256k1::Keypair::generate().into();

    let (mut network, _) = Box::pin(Network::<P>::new(
        Arc::clone(&chain_config),
        TaskExecutor::new(shutdown_tx),
        context,
        chain_config.custody_requirement,
        keypair,
    ))
    .await?;

    let peer_id = network.local_peer_id;
    let topic = config.topic();
    let topic_hash = Topic::from(topic.clone()).hash();

    // Only O joins the mesh. Publishers send without subscribing.
    if role == Role::O && !network.subscribe(topic.clone()) {
        return Err(anyhow!(
            "O could not subscribe to the execution_proof topic"
        ));
    }

    let (commands, command_receiver) = tokio_mpsc::unbounded_channel();

    let task = IdentityTask {
        role,
        network,
        grandine_peer_id: config.grandine_peer_id,
        grandine_address: config.grandine_address.clone(),
        connected_to_grandine: false,
        last_dial: Instant::now(),
        status: config.status,
        topic,
        topic_hash,
        events,
        grandine_subscribed: false,
        mesh: BTreeSet::new(),
    };

    tokio::spawn(task.run(command_receiver));

    Ok(IdentityHandle {
        role,
        peer_id,
        commands,
    })
}

struct IdentityTask<P: Preset> {
    role: Role,
    network: Network<P>,
    grandine_peer_id: PeerId,
    grandine_address: Multiaddr,
    connected_to_grandine: bool,
    last_dial: Instant,
    status: StatusMessage,
    topic: GossipTopic,
    topic_hash: TopicHash,
    events: tokio_mpsc::UnboundedSender<TimedEvent>,
    grandine_subscribed: bool,
    mesh: BTreeSet<PeerId>,
}

impl<P: Preset> IdentityTask<P> {
    async fn run(mut self, mut commands: tokio_mpsc::UnboundedReceiver<Command>) {
        let mut poll = tokio::time::interval(STATE_POLL_INTERVAL);
        poll.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                event = self.network.next_event() => self.handle_network_event(event),
                command = commands.recv() => match command {
                    Some(Command::Publish { message, reply }) => {
                        // The run may have stopped waiting for the reply.
                        reply.send(self.publish(message)).ok();
                    }
                    None => return,
                },
                _ = poll.tick() => self.poll_state(),
            }
        }
    }

    fn emit(&self, event: IdentityEvent) {
        // The run may have finished and dropped the receiver.
        self.events
            .send(TimedEvent {
                time: Utc::now(),
                role: self.role,
                event,
            })
            .ok();
    }

    fn handle_network_event(&mut self, event: NetworkEvent<P>) {
        match event {
            NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                self.emit(IdentityEvent::Connection {
                    peer_id,
                    connected: true,
                });

                if peer_id == self.grandine_peer_id {
                    self.connected_to_grandine = true;

                    let request = RequestType::Status(self.status);

                    if let Err((_, error)) =
                        self.network
                            .send_request(peer_id, AppRequestId::Application(0), request)
                    {
                        tracing::warn!(role = %self.role, ?error, "could not send Status");
                    }
                }
            }
            NetworkEvent::PeerConnectedIncoming(peer_id) => self.emit(IdentityEvent::Connection {
                peer_id,
                connected: true,
            }),
            NetworkEvent::PeerDisconnected(peer_id) => {
                if peer_id == self.grandine_peer_id {
                    self.connected_to_grandine = false;
                }

                self.emit(IdentityEvent::Connection {
                    peer_id,
                    connected: false,
                });
            }
            NetworkEvent::RequestReceived {
                peer_id,
                inbound_request_id,
                request_type,
            } => match request_type {
                RequestType::Status(remote) => {
                    self.network.send_response(
                        peer_id,
                        inbound_request_id,
                        Response::<P>::Status(remote),
                    );
                }
                // Ping, MetaData and Goodbye do not reach the application.
                _ => self.network.send_response(
                    peer_id,
                    inbound_request_id,
                    RpcResponse::<P>::Error(
                        RpcErrorResponse::ResourceUnavailable,
                        "the execution proof publisher serves no chain data".into(),
                    ),
                ),
            },
            NetworkEvent::PubsubMessage {
                id,
                source,
                message,
                ..
            } => {
                self.network.report_message_validation_result(
                    &source,
                    id.clone(),
                    MessageAcceptance::Ignore,
                );

                if let PubsubMessage::ExecutionProof(signed) = message {
                    match receipt(source, id, &signed) {
                        Ok(event) => self.emit(event),
                        Err(error) => {
                            tracing::warn!(role = %self.role, ?error, "could not record receipt");
                        }
                    }
                }
            }
            NetworkEvent::RPCFailed { peer_id, error, .. } => {
                tracing::debug!(role = %self.role, %peer_id, ?error, "RPC request failed");
            }
            NetworkEvent::ResponseReceived { .. }
            | NetworkEvent::StatusPeer(_)
            | NetworkEvent::NewListenAddr(_)
            | NetworkEvent::ZeroListeners
            | NetworkEvent::PeerUpdatedCustodyGroupCount(_) => {}
        }
    }

    fn publish(&mut self, message: Arc<SignedExecutionProofEnvelope>) -> Result<MessageId> {
        let message = PubsubMessage::<P>::ExecutionProof(message);

        let data = message
            .encode(GossipEncoding::default())
            .map_err(|error| anyhow!("could not encode the message: {error:?}"))?;

        self.network
            .gossipsub_mut()
            .publish(Topic::from(self.topic.clone()), data)
            .map_err(|error| anyhow!("gossipsub refused the message: {error:?}"))
    }

    fn poll_state(&mut self) {
        if !self.connected_to_grandine && self.last_dial.elapsed() >= REDIAL_INTERVAL {
            self.last_dial = Instant::now();

            // `testing_dial` is `eth2_libp2p`'s only dial by address. The
            // boot-node dial at startup is not retried.
            if let Err(error) = self.network.testing_dial(self.grandine_address.clone()) {
                tracing::debug!(role = %self.role, ?error, "could not redial Grandine");
            }
        }

        let grandine_subscribed = self
            .network
            .gossipsub()
            .all_peers()
            .any(|(peer_id, topics)| {
                *peer_id == self.grandine_peer_id && topics.contains(&&self.topic_hash)
            });

        if grandine_subscribed && !self.grandine_subscribed {
            self.emit(IdentityEvent::GrandineSubscribed);
        }

        self.grandine_subscribed = grandine_subscribed;

        if self.role == Role::O {
            let mesh = self
                .network
                .gossipsub()
                .mesh_peers(&self.topic_hash)
                .copied()
                .collect::<BTreeSet<_>>();

            if mesh != self.mesh {
                self.emit(IdentityEvent::Mesh {
                    peers: mesh.iter().copied().collect(),
                });
                self.mesh = mesh;
            }
        }
    }
}

fn receipt(
    source: PeerId,
    message_id: MessageId,
    signed: &SignedExecutionProofEnvelope,
) -> Result<IdentityEvent> {
    Ok(IdentityEvent::Receipt {
        source,
        message_id,
        key: ProofKey {
            block_root: signed.message.beacon_block_root,
            proof_type: signed.message.proof_type,
            validator_index: signed.validator_index,
        },
        envelope_root: signed.message.hash_tree_root(),
        ssz_sha256: sha256_hex(&signed.to_ssz()?),
    })
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;

    hex::encode(sha2::Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use bls::SignatureBytes;
    use eth2_libp2p::{libp2p::multiaddr::Protocol, rpc::StatusMessageV2};
    use ssz::ByteList;
    use tokio::time::timeout;
    use types::{
        eip8025::containers::{ExecutionProofEnvelope, ProofData},
        preset::Mainnet,
    };

    use super::*;

    const TIMEOUT: Duration = Duration::from_mins(1);

    // A stand-in for Grandine: it subscribes to the topic, answers Status and
    // ACCEPTs every message, so gossipsub forwards it.
    async fn spawn_accepting_node(
        chain_config: &Arc<Config>,
        fork_context: &Arc<ForkContext>,
        topic: GossipTopic,
    ) -> Result<(PeerId, Multiaddr)> {
        let mut network_config = NetworkConfig::default();
        network_config.set_ipv4_listening_address(Ipv4Addr::LOCALHOST, 0, 0, 0);
        network_config.network_dir = None;
        network_config.disable_discovery = true;
        network_config.disable_quic_support = true;
        network_config.upnp_enabled = false;
        network_config.enable_execution_proof = true;

        let (shutdown_tx, _) = mpsc::channel(1);

        let (mut node, _) = Box::pin(Network::<Mainnet>::new(
            Arc::clone(chain_config),
            TaskExecutor::new(shutdown_tx),
            Context {
                chain_config: Arc::clone(chain_config),
                config: Arc::new(network_config),
                enr_fork_id: EnrForkId {
                    fork_digest: fork_context.current_fork_digest(),
                    next_fork_version: chain_config.version(Phase::Gloas),
                    next_fork_epoch: FAR_FUTURE_EPOCH,
                },
                fork_context: Arc::clone(fork_context),
                libp2p_registry: None,
            },
            chain_config.custody_requirement,
            secp256k1::Keypair::generate().into(),
        ))
        .await?;

        assert!(node.subscribe(topic));

        let address = loop {
            if let NetworkEvent::NewListenAddr(address) = node.next_event().await
                && address
                    .iter()
                    .any(|protocol| matches!(protocol, Protocol::Tcp(_)))
            {
                break address;
            }
        };

        let peer_id = node.local_peer_id;

        tokio::spawn(async move {
            loop {
                match node.next_event().await {
                    NetworkEvent::RequestReceived {
                        peer_id,
                        inbound_request_id,
                        request_type: RequestType::Status(remote),
                    } => node.send_response(
                        peer_id,
                        inbound_request_id,
                        Response::<Mainnet>::Status(remote),
                    ),
                    NetworkEvent::PubsubMessage { id, source, .. } => {
                        node.report_message_validation_result(
                            &source,
                            id,
                            MessageAcceptance::Accept,
                        );
                    }
                    _ => {}
                }
            }
        });

        Ok((peer_id, address))
    }

    #[tokio::test]
    async fn o_receives_what_the_peer_forwards_from_a_publisher() -> Result<()> {
        let chain_config = Arc::new(Config::mainnet().start_and_stay_in(Phase::Gloas));
        let fork_context = Arc::new(ForkContext::dummy::<Mainnet>(&chain_config, Phase::Gloas));

        let status = StatusMessage::V2(StatusMessageV2 {
            fork_digest: fork_context.current_fork_digest(),
            finalized_root: H256::zero(),
            finalized_epoch: 0,
            head_root: H256::zero(),
            head_slot: 0,
            earliest_available_slot: 0,
        });

        let mut config = IdentityConfig {
            chain_config: Arc::clone(&chain_config),
            fork_context: Arc::clone(&fork_context),
            grandine_peer_id: PeerId::random(),
            grandine_address: Multiaddr::empty(),
            current_phase: Phase::Gloas,
            status,
        };

        let (node_peer_id, node_address) =
            spawn_accepting_node(&chain_config, &fork_context, config.topic()).await?;

        config.grandine_peer_id = node_peer_id;
        config.grandine_address = node_address;

        let (sender, mut events) = tokio_mpsc::unbounded_channel();
        let mut handles = vec![];

        let deadline = Instant::now() + TIMEOUT;

        // One at a time, as the run starts them.
        for role in Role::ALL {
            handles.push(spawn::<Mainnet>(role, &config, sender.clone()).await?);

            loop {
                let event = timeout(deadline - Instant::now(), events.recv())
                    .await?
                    .expect("the identities are running");

                if let IdentityEvent::Connection {
                    peer_id,
                    connected: true,
                } = event.event
                    && event.role == role
                    && peer_id == node_peer_id
                {
                    break;
                }
            }
        }

        // Step 0's condition: every identity sees the peer subscribed, and the
        // peer is in O's mesh.
        let mut subscribed = BTreeSet::new();
        let mut in_mesh = false;
        let mut foreign_peers = BTreeSet::new();

        while subscribed.len() < Role::ALL.len() || !in_mesh {
            let event = timeout(deadline - Instant::now(), events.recv())
                .await?
                .expect("the identities are running");

            match event.event {
                IdentityEvent::GrandineSubscribed => {
                    subscribed.insert(event.role);
                }
                IdentityEvent::Mesh { peers } if event.role == Role::O => {
                    in_mesh = peers.contains(&node_peer_id);
                }
                IdentityEvent::Connection { peer_id, .. } if peer_id != node_peer_id => {
                    foreign_peers.insert(peer_id);
                }
                _ => {}
            }
        }

        assert!(foreign_peers.is_empty(), "identities only dial the peer");

        let message = Arc::new(SignedExecutionProofEnvelope {
            message: ExecutionProofEnvelope {
                proof_data: ProofData::from(ByteList::try_from(vec![0xcd; 1024])?),
                proof_type: 1,
                beacon_block_root: H256::repeat_byte(0xbb),
            }
            .into(),
            validator_index: 11,
            signature: SignatureBytes::default(),
        });

        let publisher = handles
            .iter()
            .find(|handle| handle.role() == Role::Pa)
            .expect("P_a is running");

        let message_id = publisher.publish(Arc::clone(&message)).await?;

        loop {
            let event = timeout(deadline - Instant::now(), events.recv())
                .await?
                .expect("the identities are running");

            if let (
                Role::O,
                IdentityEvent::Receipt {
                    source,
                    message_id: received,
                    ssz_sha256,
                    ..
                },
            ) = (event.role, event.event)
            {
                assert_eq!(source, node_peer_id);
                assert_eq!(received, message_id);
                assert_eq!(ssz_sha256, sha256_hex(&message.to_ssz()?));
                return Ok(());
            }
        }
    }
}
