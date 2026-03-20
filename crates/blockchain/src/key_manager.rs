use std::collections::HashMap;

use ethlambda_types::{
    attestation::{AttestationData, XmssSignature},
    primitives::{H256, ssz::TreeHash},
    signature::{ValidatorSecretKey, ValidatorSignature},
};

use crate::metrics;

/// Error types for KeyManager operations.
#[derive(Debug, thiserror::Error)]
pub enum KeyManagerError {
    #[error("Validator key not found for validator_id: {0}")]
    ValidatorKeyNotFound(u64),
    #[error("Signing error: {0}")]
    SigningError(String),
    #[error("Signature conversion error: {0}")]
    SignatureConversionError(String),
}

pub struct ValidatorKeyPair {
    pub attestation_key: ValidatorSecretKey,
    pub proposal_key: ValidatorSecretKey,
}

pub struct KeyManager {
    keys: HashMap<u64, ValidatorKeyPair>,
}

impl KeyManager {
    pub fn new(keys: HashMap<u64, ValidatorKeyPair>) -> Self {
        Self { keys }
    }

    pub fn validator_ids(&self) -> Vec<u64> {
        self.keys.keys().copied().collect()
    }

    pub fn sign_attestation(
        &mut self,
        validator_id: u64,
        attestation_data: &AttestationData,
    ) -> Result<XmssSignature, KeyManagerError> {
        let message = attestation_data.tree_hash_root();
        let slot = attestation_data.slot as u32;
        let key_pair = self
            .keys
            .get_mut(&validator_id)
            .ok_or(KeyManagerError::ValidatorKeyNotFound(validator_id))?;
        let sig = Self::sign_with_key(&mut key_pair.attestation_key, slot, &message)?;
        metrics::inc_pq_sig_attestation_signatures();
        Ok(sig)
    }

    pub fn sign_block_root(
        &mut self,
        validator_id: u64,
        slot: u32,
        block_root: &H256,
    ) -> Result<XmssSignature, KeyManagerError> {
        let key_pair = self
            .keys
            .get_mut(&validator_id)
            .ok_or(KeyManagerError::ValidatorKeyNotFound(validator_id))?;
        Self::sign_with_key(&mut key_pair.proposal_key, slot, block_root)
    }

    fn sign_with_key(
        key: &mut ValidatorSecretKey,
        slot: u32,
        message: &H256,
    ) -> Result<XmssSignature, KeyManagerError> {
        let signature: ValidatorSignature = {
            let _timing = metrics::time_pq_sig_attestation_signing();
            key.sign(slot, message)
                .map_err(|e| KeyManagerError::SigningError(e.to_string()))
        }?;
        XmssSignature::try_from(signature.to_bytes())
            .map_err(|e| KeyManagerError::SignatureConversionError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_ids() {
        let keys = HashMap::new();
        let key_manager = KeyManager::new(keys);
        assert_eq!(key_manager.validator_ids().len(), 0);
    }

    #[test]
    fn test_sign_attestation_validator_not_found() {
        let keys = HashMap::new();
        let mut key_manager = KeyManager::new(keys);
        let data = AttestationData {
            slot: 0,
            head: Default::default(),
            target: Default::default(),
            source: Default::default(),
        };

        let result = key_manager.sign_attestation(123, &data);
        assert!(matches!(
            result,
            Err(KeyManagerError::ValidatorKeyNotFound(123))
        ));
    }

    #[test]
    fn test_sign_block_root_validator_not_found() {
        let keys = HashMap::new();
        let mut key_manager = KeyManager::new(keys);
        let message = H256::default();

        let result = key_manager.sign_block_root(123, 0, &message);
        assert!(matches!(
            result,
            Err(KeyManagerError::ValidatorKeyNotFound(123))
        ));
    }
}
