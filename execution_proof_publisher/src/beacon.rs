use core::time::Duration;

use anyhow::{Context as _, Result, bail};
use eth2_libp2p::Multiaddr;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;
use types::{
    gloas::containers::{SignedExecutionPayloadBid, SignedExecutionPayloadEnvelope},
    phase0::{
        containers::Fork,
        primitives::{Epoch, H256, Slot, UnixSeconds, ValidatorIndex},
    },
    preset::Preset,
    redacting_url::RedactingUrl,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The `data` of a Beacon API response, with the metadata the publisher reads.
///
/// `canonical` is not read: Grandine reports it as the constant `true`.
#[derive(Deserialize)]
struct Response<T> {
    data: T,
    #[serde(default)]
    execution_optimistic: Option<bool>,
    #[serde(default)]
    finalized: Option<bool>,
}

#[derive(Deserialize)]
pub struct Identity {
    pub peer_id: String,
    pub p2p_addresses: Vec<Multiaddr>,
}

#[derive(Deserialize)]
pub struct Genesis {
    #[serde(with = "serde_utils::string_or_native")]
    pub genesis_time: UnixSeconds,
    pub genesis_validators_root: H256,
}

#[derive(Deserialize)]
pub struct Syncing {
    pub is_syncing: bool,
}

#[derive(Deserialize)]
struct HeaderData {
    root: H256,
    header: SignedHeader,
}

#[derive(Deserialize)]
struct SignedHeader {
    message: HeaderMessage,
}

#[derive(Deserialize)]
struct HeaderMessage {
    #[serde(with = "serde_utils::string_or_native")]
    slot: Slot,
}

/// A block header as one Beacon API lookup reported it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Header {
    pub root: H256,
    pub slot: Slot,
    pub finalized: Option<bool>,
}

#[derive(Deserialize)]
struct FinalityCheckpoints {
    finalized: Checkpoint,
}

#[derive(Deserialize)]
pub struct Checkpoint {
    #[serde(with = "serde_utils::string_or_native")]
    pub epoch: Epoch,
    pub root: H256,
}

#[derive(Deserialize)]
struct ValidatorData {
    #[serde(with = "serde_utils::string_or_native")]
    index: ValidatorIndex,
    status: String,
}

/// A validator as the Beacon API reported it at one state.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ValidatorStatus {
    pub index: ValidatorIndex,
    pub status: String,
}

impl ValidatorStatus {
    /// Whether the status is one of the `active_*` statuses, which are the
    /// ones `is_active_validator` accepts.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status.starts_with("active_")
    }
}

/// The parts of B's payload envelope the publisher binds a proof to.
pub struct Envelope<P: Preset> {
    pub envelope: SignedExecutionPayloadEnvelope<P>,
    pub execution_optimistic: Option<bool>,
}

pub struct BeaconClient {
    client: Client,
    base_url: RedactingUrl,
}

impl BeaconClient {
    pub fn new(base_url: RedactingUrl) -> Result<Self> {
        let client = Client::builder().timeout(REQUEST_TIMEOUT).build()?;
        Ok(Self { client, base_url })
    }

    pub async fn identity(&self) -> Result<Identity> {
        Ok(self.get::<Identity>("/eth/v1/node/identity").await?.data)
    }

    pub async fn genesis(&self) -> Result<Genesis> {
        Ok(self.get::<Genesis>("/eth/v1/beacon/genesis").await?.data)
    }

    pub async fn syncing(&self) -> Result<Syncing> {
        Ok(self.get::<Syncing>("/eth/v1/node/syncing").await?.data)
    }

    pub async fn head_header(&self) -> Result<Header> {
        let response = self
            .get::<HeaderData>("/eth/v1/beacon/headers/head")
            .await?;
        Ok(header(&response))
    }

    /// The header Grandine returns for a slot, or `None` if the slot is empty
    /// on the chain of its current head.
    pub async fn header_by_slot(&self, slot: Slot) -> Result<Option<Header>> {
        let path = format!("/eth/v1/beacon/headers?slot={slot}");

        let Some(response) = self.get_optional::<Vec<HeaderData>>(&path).await? else {
            return Ok(None);
        };

        let Response {
            data,
            execution_optimistic,
            finalized,
        } = response;

        Ok(data.into_iter().next().map(|data| {
            header(&Response {
                data,
                execution_optimistic,
                finalized,
            })
        }))
    }

    pub async fn finalized_checkpoint(&self) -> Result<Checkpoint> {
        let response = self
            .get::<FinalityCheckpoints>("/eth/v1/beacon/states/head/finality_checkpoints")
            .await?;

        Ok(response.data.finalized)
    }

    pub async fn envelope<P: Preset>(&self, block_root: H256) -> Result<Option<Envelope<P>>> {
        let path = format!("/eth/v1/beacon/execution_payload_envelopes/{block_root:?}");

        Ok(self
            .get_optional::<SignedExecutionPayloadEnvelope<P>>(&path)
            .await?
            .map(|response| Envelope {
                envelope: response.data,
                execution_optimistic: response.execution_optimistic,
            }))
    }

    /// The signed bid in a Gloas block, which carries the blob commitments
    /// the proof's versioned hashes come from.
    pub async fn bid<P: Preset>(&self, block_root: H256) -> Result<SignedExecutionPayloadBid<P>> {
        let path = format!("/eth/v2/beacon/blocks/{block_root:?}");
        let response = self.get::<Value>(&path).await?;

        let bid = response
            .data
            .pointer("/message/body/signed_execution_payload_bid")
            .cloned()
            .with_context(|| format!("block {block_root:?} has no execution payload bid"))?;

        Ok(serde_json::from_value(bid)?)
    }

    pub async fn fork(&self, slot: Slot) -> Result<Fork> {
        let path = format!("/eth/v1/beacon/states/{slot}/fork");
        Ok(self.get::<Fork>(&path).await?.data)
    }

    pub async fn validator(&self, slot: Slot, pubkey: &str) -> Result<Option<ValidatorStatus>> {
        let path = format!("/eth/v1/beacon/states/{slot}/validators/{pubkey}");

        Ok(self
            .get_optional::<ValidatorData>(&path)
            .await?
            .map(|response| ValidatorStatus {
                index: response.data.index,
                status: response.data.status,
            }))
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<Response<T>> {
        self.get_optional(path)
            .await?
            .with_context(|| format!("GET {path} returned 404"))
    }

    async fn get_optional<T: DeserializeOwned>(&self, path: &str) -> Result<Option<Response<T>>> {
        let url = self.base_url.join(path)?.into_url();
        let response = self.client.get(url).send().await?;

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !response.status().is_success() {
            bail!("GET {path} returned {}", response.status());
        }

        let bytes = response.bytes().await?;

        serde_json::from_slice(&bytes)
            .with_context(|| format!("GET {path} returned an unexpected body"))
            .map(Some)
    }
}

const fn header(response: &Response<HeaderData>) -> Header {
    Header {
        root: response.data.root,
        slot: response.data.header.message.slot,
        finalized: response.finalized,
    }
}

#[cfg(test)]
mod tests {
    use crate::target::{Eligibility, Target};

    use super::*;

    fn by_slot_response(canonical: bool, finalized: bool) -> String {
        format!(
            r#"{{
                "execution_optimistic": false,
                "finalized": {finalized},
                "data": [{{
                    "root": "0x{root}",
                    "canonical": {canonical},
                    "header": {{
                        "message": {{
                            "slot": "39",
                            "proposer_index": "1",
                            "parent_root": "0x{zero}",
                            "state_root": "0x{zero}",
                            "body_root": "0x{zero}"
                        }},
                        "signature": "0x{signature}"
                    }}
                }}]
            }}"#,
            root = "01".repeat(32),
            zero = "00".repeat(32),
            signature = "00".repeat(96),
        )
    }

    fn eligibility(json: &str) -> Eligibility {
        let response = serde_json::from_str::<Response<Vec<HeaderData>>>(json)
            .expect("the fixture is a by-slot headers response");

        let Response {
            data,
            execution_optimistic,
            finalized,
        } = response;

        let header = data.into_iter().next().map(|data| {
            header(&Response {
                data,
                execution_optimistic,
                finalized,
            })
        });

        let target = Target {
            block_root: H256::repeat_byte(1),
            slot: 39,
        };

        Eligibility::from_lookup(target, header)
    }

    #[test]
    fn eligibility_ignores_canonical() {
        assert_eq!(
            eligibility(&by_slot_response(false, false)),
            Eligibility::Eligible
        );
        assert_eq!(
            eligibility(&by_slot_response(true, true)),
            Eligibility::Finalized
        );
    }
}
