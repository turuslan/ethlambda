use serde::Serialize;
use ssz_types::typenum::U1048576;

use crate::{
    attestation::{AggregatedAttestation, AggregationBits, XmssSignature, validator_indices},
    primitives::{
        ByteList, H256,
        ssz::{Decode, Encode, TreeHash},
    },
    state::ValidatorRegistryLimit,
};

#[derive(Clone, Encode, Decode)]
pub struct SignedBlock {
    pub message: Block,
    pub signature: BlockSignatures,
}

// Manual Debug impl because leanSig signatures don't implement Debug.
impl core::fmt::Debug for SignedBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignedBlock")
            .field("message", &self.message)
            .field("signature", &"...")
            .finish()
    }
}

#[derive(Clone, Encode, Decode)]
pub struct BlockSignatures {
    /// One aggregated proof per attestation in the block body.
    pub attestation_signatures: AttestationSignatures,
    /// Proposer's signature over `hash_tree_root(block)` using the proposal key.
    pub proposer_signature: XmssSignature,
}

pub type AttestationSignatures =
    ssz_types::VariableList<AggregatedSignatureProof, ValidatorRegistryLimit>;

/// Aggregated leanVM signature proof covering a set of validators.
#[derive(Debug, Clone, Encode, Decode)]
pub struct AggregatedSignatureProof {
    pub participants: AggregationBits,
    pub proof_data: ByteListMiB,
}

pub type ByteListMiB = ByteList<U1048576>;

impl AggregatedSignatureProof {
    pub fn new(participants: AggregationBits, proof_data: ByteListMiB) -> Self {
        Self {
            participants,
            proof_data,
        }
    }

    /// Empty proof (placeholder for test paths without real aggregation).
    pub fn empty(participants: AggregationBits) -> Self {
        Self {
            participants,
            proof_data: ByteList::empty(),
        }
    }

    pub fn participant_indices(&self) -> impl Iterator<Item = u64> + '_ {
        validator_indices(&self.participants)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Encode, Decode, TreeHash)]
pub struct BlockHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: H256,
    pub state_root: H256,
    pub body_root: H256,
}

#[derive(Debug, Clone, Encode, Decode, TreeHash)]
pub struct Block {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: H256,
    pub state_root: H256,
    pub body: BlockBody,
}

impl Block {
    pub fn header(&self) -> BlockHeader {
        BlockHeader {
            slot: self.slot,
            proposer_index: self.proposer_index,
            parent_root: self.parent_root,
            state_root: self.state_root,
            body_root: self.body.tree_hash_root(),
        }
    }

    pub fn from_header_and_body(header: BlockHeader, body: BlockBody) -> Self {
        debug_assert_eq!(
            header.body_root,
            body.tree_hash_root(),
            "body root mismatch"
        );
        Self {
            slot: header.slot,
            proposer_index: header.proposer_index,
            parent_root: header.parent_root,
            state_root: header.state_root,
            body,
        }
    }
}

#[derive(Debug, Default, Clone, Encode, Decode, TreeHash)]
pub struct BlockBody {
    pub attestations: AggregatedAttestations,
}

pub type AggregatedAttestations =
    ssz_types::VariableList<AggregatedAttestation, ValidatorRegistryLimit>;
