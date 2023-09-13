use std::str::FromStr;

use hex::{FromHex, ToHex};
use monero::{
    blockdata::transaction::{ExtraField, KeyImage, RawExtraField, SubField, TxOutTarget},
    consensus::{deserialize, serialize},
    cryptonote::hash::Hashable,
    util::{
        key::H,
        ringct::{CtKey, EcdhInfo, Key, RctSig, RctSigBase, RctType},
    },
    Amount,
    Block,
    BlockHeader,
    Hash,
    PrivateKey,
    PublicKey,
    Transaction,
    TransactionPrefix,
    TxIn,
    TxOut,
    VarInt,
    ViewPair,
};

/// monero_block_deserialize, called from the fuzz target
pub fn fuzz_monero_block_deserialize(fuzz_data: &[u8]) {
    let fuzz_bytes = fuzz_data.to_vec();

    // Block
    if let Ok(val) = deserialize::<Block>(&fuzz_bytes[..]) {
        if let Ok(bytes2) = serialize(&val) {
            assert_eq!(fuzz_bytes, bytes2);
        }
    }
}

/// monero_block_header_deserialize, called from the fuzz target
pub fn fuzz_monero_block_header_deserialize(fuzz_data: &[u8]) {
    let fuzz_bytes = fuzz_data.to_vec();

    // BlockHeader
    if let Ok(val) = deserialize::<BlockHeader>(&fuzz_bytes[..]) {
        if let Ok(bytes2) = serialize(&val) {
            assert_eq!(fuzz_bytes, bytes2);
        }
    }
}

/// monero_transaction_prefix_deserialize, called from the fuzz target
pub fn fuzz_monero_transaction_prefix_deserialize(fuzz_data: &[u8]) {
    let fuzz_bytes = fuzz_data.to_vec();

    // TransactionPrefix
    if let Ok(val) = deserialize::<TransactionPrefix>(&fuzz_bytes[..]) {
        if let Ok(bytes2) = serialize(&val) {
            assert_eq!(fuzz_bytes, bytes2);
        }
    }
}

/// monero_transaction_deserialize, called from the fuzz target
pub fn fuzz_monero_transaction_deserialize(fuzz_data: &[u8]) {
    let fuzz_bytes = fuzz_data.to_vec();

    // Transaction
    if let Ok(val) = deserialize::<Transaction>(&fuzz_bytes[..]) {
        if let Ok(bytes2) = serialize(&val) {
            assert_eq!(fuzz_bytes, bytes2);
        }
    }
}

/// monero_transaction_serialize_deserialize, called from the fuzz target
pub fn fuzz_monero_transaction_serialize_deserialize(transaction: &Transaction) {
    let transaction_hex = match serialize(transaction) {
        Ok(val) => val,
        Err(_) => {
            // This may not fail, otherwise the test cannot continue
            return;
        },
    };

    // Transaction
    match deserialize::<Transaction>(&transaction_hex[..]) {
        Ok(val) => {
            assert_eq!(transaction, &val);
        },
        Err(err) => {
            panic!(
                "Deserializing a serialized transaction may not fail ({})",
                err.to_string()
            );
        },
    }
}

/// monero_hash_convert, called from the fuzz target
pub fn fuzz_monero_hash_convert(fuzz_data: &[u8]) {
    // Hash
    let hash = Hash::new(fuzz_data);

    let hash_str: String = hash.encode_hex();
    if let Ok(hash2) = Hash::from_hex(hash_str.clone()) {
        assert_eq!(hash, hash2);
    }

    let hash_str_with_0x = format!("0x{hash_str}");
    if let Ok(hash2) = Hash::from_hex(hash_str_with_0x) {
        assert_eq!(hash, hash2);
    }

    assert_eq!(hash.as_scalar(), Hash::hash_to_scalar(fuzz_data));
}

/// monero_create_extra_field, called from the fuzz target
pub fn fuzz_monero_create_extra_field(fuzz_data: &[u8]) -> ExtraField {
    let fuzz_bytes = fuzz_data.to_vec();
    let hash = Hash::new(fuzz_data);

    // SubField
    let nonce_field = SubField::Nonce(fuzz_bytes.clone());
    let padding_field = if fuzz_bytes.is_empty() {
        SubField::Padding(u8::MIN)
    } else {
        SubField::Padding(fuzz_bytes[0])
    };
    let u64_val = if fuzz_bytes.is_empty() {
        0
    } else {
        let mut vec = fuzz_bytes.clone();
        vec.resize(8, 0);
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(vec.as_slice());
        u64::from_le_bytes(bytes)
    };
    let merge_mining_field = SubField::MergeMining(Some(VarInt(u64_val)), hash);
    let mysterious_miner_gate_field = SubField::MysteriousMinerGate(fuzz_bytes);

    // ExtraField
    ExtraField(vec![
        nonce_field,
        padding_field,
        merge_mining_field,
        mysterious_miner_gate_field,
    ])
}

/// monero_raw_extra_field_deserialize, called from the fuzz target
pub fn fuzz_monero_raw_extra_field_deserialize(raw_extra_field: &RawExtraField) {
    let raw_extra_field_bytes = match serialize(raw_extra_field) {
        Ok(val) => val,
        Err(_) => {
            // This may not fail, otherwise the test cannot continue
            return;
        },
    };
    if let Ok(raw_extra_field_2) = deserialize::<RawExtraField>(&raw_extra_field_bytes) {
        assert_eq!(raw_extra_field, &raw_extra_field_2);
    }
}

/// monero_extra_field_try_parse, called from the fuzz target
pub fn fuzz_monero_extra_field_try_parse(extra_field: &ExtraField) {
    let raw_extra_field = match RawExtraField::try_from(extra_field.clone()) {
        Ok(val) => val,
        Err(_) => {
            // This may not fail, otherwise the test cannot continue
            return;
        },
    };
    if let Ok(extra_field_2) = ExtraField::try_parse(&raw_extra_field) {
        assert_eq!(extra_field, &extra_field_2);
    }
}

/// monero_create_transaction, called from the fuzz target
pub fn fuzz_monero_create_transaction(fuzz_data: &[u8], raw_extra_field: &RawExtraField) -> Transaction {
    let fuzz_bytes = fuzz_data.to_vec();
    let hash = Hash::new(fuzz_data);
    let u64_val = if fuzz_bytes.is_empty() {
        0
    } else {
        let mut vec = fuzz_bytes.clone();
        vec.resize(8, 0);
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(vec.as_slice());
        u64::from_le_bytes(bytes)
    };

    let prefix = TransactionPrefix {
        version: VarInt(u64_val),
        unlock_time: VarInt(u64_val),
        inputs: vec![
            TxIn::Gen {
                height: VarInt(u64_val),
            },
            TxIn::ToKey {
                amount: VarInt(u64_val),
                key_offsets: vec![VarInt(u64_val)],
                k_image: KeyImage { image: hash },
            },
        ],
        outputs: vec![TxOut {
            amount: VarInt(u64_val),
            target: TxOutTarget::ToScript {
                keys: vec![H, H + H],
                script: fuzz_bytes,
            },
        }],
        extra: raw_extra_field.clone(),
    };

    let rct_signatures = RctSig {
        sig: Option::from(RctSigBase {
            rct_type: RctType::Full,
            txn_fee: Amount::from_pico(u64_val),
            pseudo_outs: vec![Key { key: hash.0 }],
            ecdh_info: vec![EcdhInfo::Standard {
                mask: Key { key: hash.0 },
                amount: Key { key: hash.0 },
            }],
            out_pk: vec![CtKey {
                mask: Key { key: hash.0 },
            }],
        }),
        p: None,
    };

    Transaction {
        prefix,
        signatures: vec![],
        rct_signatures,
    }
}

/// monero_transaction_hash, called from the fuzz target
pub fn fuzz_monero_transaction_hash(transaction: &Transaction) {
    let _hash = transaction.hash();
}

/// monero_transaction_check_outputs, called from the fuzz target
pub fn fuzz_monero_transaction_check_outputs(transaction: &Transaction) {
    let secret_view = match PrivateKey::from_str("bcfdda53205318e1c14fa0ddca1a45df363bb427972981d0249d0f4652a7df07") {
        Ok(val) => val,
        Err(_) => {
            // This may not fail, otherwise the test cannot continue
            return;
        },
    };
    let secret_spend = match PrivateKey::from_str("e5f4301d32f3bdaef814a835a18aaaa24b13cc76cf01a832a7852faf9322e907") {
        Ok(val) => val,
        Err(_) => {
            // This may not fail, otherwise the test cannot continue
            return;
        },
    };
    let public_spend = PublicKey::from_private_key(&secret_spend);
    let viewpair = ViewPair {
        view: secret_view,
        spend: public_spend,
    };

    if transaction.check_outputs(&viewpair, 0..3, 0..3).is_ok() {}
}

#[cfg(test)]
mod tests {
    use monero::blockdata::transaction::RawExtraField;
    use rand::Rng;

    use crate::monero_fuzz::{
        fuzz_monero_block_deserialize,
        fuzz_monero_block_header_deserialize,
        fuzz_monero_create_extra_field,
        fuzz_monero_create_transaction,
        fuzz_monero_extra_field_try_parse,
        fuzz_monero_hash_convert,
        fuzz_monero_raw_extra_field_deserialize,
        fuzz_monero_transaction_check_outputs,
        fuzz_monero_transaction_deserialize,
        fuzz_monero_transaction_hash,
        fuzz_monero_transaction_prefix_deserialize,
        fuzz_monero_transaction_serialize_deserialize,
    };

    #[test]
    fn test_fuzz_monero_block_deserialize() {
        let mut rng = rand::thread_rng();
        for i in 0..128 {
            let data: Vec<u8> = if i == 0 {
                Vec::new()
            } else {
                (0..i).map(|_| rng.gen()).collect()
            };
            fuzz_monero_block_deserialize(&data);
        }
    }

    #[test]
    fn test_failing_monero_block_deserialize() {
        let data = [];
        fuzz_monero_block_deserialize(&data);
        let data = [
            0, 0, 0, 10, 33, 10, 2, 2, 2, 6, 167, 175, 253, 167, 167, 167, 167, 167, 167, 167, 89, 88, 88, 88, 88, 88,
            88, 88, 167, 167, 167, 0, 167, 145, 145, 145, 145, 145, 2, 253, 253, 126, 0, 1, 255, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 63, 140, 29, 29, 233, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
            29, 29, 3, 3, 3, 3, 3, 2, 63, 140, 29, 29, 233, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
            29, 29, 29, 29, 29, 29, 29, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 29, 29, 29, 29, 29,
            29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 102, 102, 102, 102, 102, 102,
            102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102,
            102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 29, 29, 29, 29, 29, 29, 29, 29, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 102,
            102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102,
            102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 29, 29, 29, 29, 29,
            29, 29, 29, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
            29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
            29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
        ];
        fuzz_monero_block_deserialize(&data);
        let data = [
            0, 0, 0, 10, 33, 10, 2, 2, 2, 6, 167, 175, 253, 167, 167, 167, 167, 167, 167, 167, 89, 88, 88, 88, 88, 88,
            88, 88, 167, 167, 167, 0, 167, 145, 145, 145, 145, 145, 2, 253, 253, 126, 0, 1, 255, 2, 2, 2, 2, 40, 2, 2,
            2, 2, 2, 63, 140, 29, 29, 233, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
            29, 29, 29, 3, 3, 3, 3, 3, 2, 63, 0, 42, 29, 233, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
            29, 29, 29, 29, 29, 29, 29, 29, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 29, 29, 29, 29,
            29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 0, 0, 0, 10, 33, 10, 2, 2, 2, 0, 0, 0, 0, 6, 253, 175, 2, 2, 253,
            253, 126, 0, 0, 255, 0, 58, 255, 255, 29, 29, 29, 29, 185, 185, 185, 185, 185, 185, 2, 2, 2, 0, 0, 0, 0,
            29, 29, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 29, 29, 29, 0, 8, 0, 0, 30, 0, 0, 0, 0, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 210, 0, 0,
            0, 210, 210, 210,
        ];
        fuzz_monero_block_deserialize(&data);
        let data = [
            0, 0, 0, 10, 33, 10, 2, 2, 2, 6, 167, 175, 253, 167, 167, 167, 167, 167, 167, 167, 89, 88, 88, 88, 88, 88,
            88, 88, 167, 167, 167, 0, 167, 145, 145, 145, 145, 145, 2, 253, 253, 126, 0, 1, 255, 2, 2, 2, 2, 40, 2, 2,
            2, 2, 2, 63, 140, 29, 29, 233, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
            29, 29, 29, 3, 3, 3, 3, 3, 2, 63, 0, 42, 29, 233, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
            29, 29, 29, 29, 29, 29, 29, 29, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 29, 29, 29, 29,
            29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 0, 0, 0, 10, 33, 10, 2, 2, 2, 0, 0, 0, 0, 6, 253, 175, 2, 2, 253,
            253, 126, 0, 0, 255, 0, 58, 255, 255, 29, 29, 29, 29, 185, 185, 185, 185, 185, 185, 2, 2, 2, 0, 0, 0, 0,
            29, 29, 29, 29, 29, 0, 8, 0, 0, 30, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 29, 29,
            29, 29, 29, 29, 29, 29, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 210, 0, 0, 0, 210, 210,
            210,
        ];
        fuzz_monero_block_deserialize(&data);
    }

    #[test]
    fn test_fuzz_monero_block_header_deserialize() {
        let mut rng = rand::thread_rng();
        for i in 0..128 {
            let data: Vec<u8> = if i == 0 {
                Vec::new()
            } else {
                (0..i).map(|_| rng.gen()).collect()
            };
            fuzz_monero_block_header_deserialize(&data);
        }
    }

    #[test]
    fn test_fuzz_monero_transaction_prefix_deserialize() {
        let mut rng = rand::thread_rng();
        for i in 0..128 {
            let data: Vec<u8> = if i == 0 {
                Vec::new()
            } else {
                (0..i).map(|_| rng.gen()).collect()
            };
            fuzz_monero_transaction_prefix_deserialize(&data);
        }
    }

    #[test]
    fn test_failing_monero_transaction_prefix_deserialize() {
        let data = [
            65, 26, 1, 2, 0, 2, 0, 0, 0, 0, 0, 0, 45, 255, 0, 0, 0, 2, 6, 0, 0, 0, 253, 0, 0, 0, 255, 0, 0, 0, 249, 2,
            0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 3, 6, 0, 0, 0, 253, 255, 255, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 2, 6, 0, 0,
            0, 253, 0, 0, 0, 255, 0, 0, 0, 249, 2, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 2, 6, 0, 0, 0, 253, 255, 255, 171,
            38, 255, 255, 255, 80, 80, 65, 255, 255, 255, 6, 0, 0, 0, 253, 0, 0, 0, 255, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0,
            255, 0, 0, 0, 2, 6, 0, 0, 0, 253, 255, 36, 79, 79, 44, 79, 171,
        ];
        fuzz_monero_transaction_prefix_deserialize(&data);
        let data = [
            5, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 248, 1, 0, 0, 0, 2, 2, 2, 1, 0,
            0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 37, 2, 2, 2, 2, 2, 2, 5, 2, 2, 2, 2, 2, 2, 62, 62, 62, 62, 62, 65, 2, 2, 2,
            2, 2, 2, 2, 2, 2, 2, 255, 255, 255, 255, 255, 251, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 3, 2, 1, 248, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 3, 255, 255, 255, 93, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2,
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 248, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 37, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 168, 71,
            251, 251, 8, 0, 1, 0, 0,
        ];
        fuzz_monero_transaction_prefix_deserialize(&data);
        let data = [
            5, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 248, 1, 0, 0, 0, 2, 2, 2, 2, 2,
            2, 2, 2, 2, 2, 2, 37, 2, 2, 2, 2, 2, 2, 5, 2, 2, 2, 2, 2, 2, 62, 62, 62, 62, 62, 62, 62, 2, 2, 2, 3, 0, 5,
            255, 255, 255, 251, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 168, 71, 251, 251, 2, 2, 2,
            2, 2, 2, 2, 2, 2, 2, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 37, 2, 2, 239, 2, 2, 2, 2, 5, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 255, 255, 255, 255, 255, 251, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 3, 131, 3, 3, 3, 3, 247, 252, 252, 252, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3,
            2, 1, 248, 2, 2, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191,
            191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191,
            191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191,
            191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191,
            191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191,
            191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191,
            191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 37,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 1, 0, 0,
        ];
        fuzz_monero_transaction_prefix_deserialize(&data);
        let data = [
            5, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 248, 1, 0, 0, 0, 2, 2, 2, 2, 2,
            2, 2, 2, 2, 2, 2, 37, 2, 2, 2, 2, 2, 2, 5, 2, 2, 2, 33, 2, 2, 62, 62, 62, 62, 62, 62, 62, 2, 2, 2, 3, 0, 5,
            255, 255, 255, 251, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 168, 71, 251, 251, 2, 2, 2,
            2, 2, 2, 2, 2, 2, 2, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 37, 2, 2, 239, 2, 2, 2, 2, 5, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 255, 255, 255, 255, 255, 251, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 2, 2, 2, 2, 2,
            2, 2, 2, 2, 2, 37, 2, 3, 3, 255, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 0, 0, 0, 6, 0, 171, 181, 181, 181, 181, 181, 181, 255, 5, 181, 181, 181, 181, 181, 181, 181,
            181, 0, 0, 0, 0, 0, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 33, 0,
            0, 0, 0, 0, 0, 227, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 149, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 255, 34, 0, 0, 0, 0, 181, 181, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 168, 71, 251, 251, 8,
            0, 1, 0, 0,
        ];
        fuzz_monero_transaction_prefix_deserialize(&data);
    }

    #[test]
    fn test_fuzz_monero_transaction_deserialize() {
        let mut rng = rand::thread_rng();
        for i in 0..128 {
            let data: Vec<u8> = if i == 0 {
                Vec::new()
            } else {
                (0..i).map(|_| rng.gen()).collect()
            };
            fuzz_monero_transaction_deserialize(&data);
        }
    }

    #[test]
    fn test_failing_monero_transaction_deserialize() {
        let data = [
            80, 80, 1, 255, 255, 15, 0, 0, 3, 61, 3, 181, 181, 181, 181, 181, 181, 181, 181, 80, 254, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255,
        ];
        fuzz_monero_transaction_deserialize(&data);
        let data = [
            80, 80, 1, 255, 255, 255, 15, 0, 0, 3, 61, 3, 181, 181, 181, 181, 181, 255, 2, 0, 0, 39, 74, 2, 0, 33, 247,
            255, 255, 255, 255, 0, 13, 0, 0, 6, 1, 0, 39, 74, 2, 255, 255, 255, 255, 255, 255, 15, 255, 255, 255,
        ];
        fuzz_monero_transaction_deserialize(&data);
        let data = [
            80, 80, 1, 255, 255, 255, 15, 0, 0, 3, 61, 3, 181, 181, 181, 181, 181, 181, 255, 2, 13, 1, 0, 2, 255, 255,
            141, 255, 6, 0, 0, 1, 255, 25, 25, 25, 25, 25, 25, 25, 25, 25, 93, 25, 25, 25, 25, 26, 25, 25, 25, 25, 25,
            4, 4, 4, 4, 4, 4, 4, 4, 4, 255, 59, 176, 46, 1, 0, 0, 0, 4, 4, 4, 4, 4, 4, 176, 25, 25, 191, 25, 25, 25,
            176, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 59, 0, 0, 0, 0, 0, 0, 181, 255, 2, 0, 181, 181, 2, 0, 0, 0, 39,
            74, 2, 255, 39, 0, 0, 0, 0,
        ];
        fuzz_monero_transaction_deserialize(&data);
    }

    #[test]
    fn test_fuzz_monero_transaction_serialize_deserialize() {
        let mut rng = rand::thread_rng();
        for i in 0..128 {
            let data: Vec<u8> = if i == 0 {
                Vec::new()
            } else {
                (0..i).map(|_| rng.gen()).collect()
            };
            let extra_field = fuzz_monero_create_extra_field(&data);
            let raw_extra_field = match RawExtraField::try_from(extra_field) {
                Ok(val) => val,
                Err(_) => {
                    // This may not fail, otherwise the test cannot continue
                    continue;
                },
            };
            let transaction = fuzz_monero_create_transaction(&data, &raw_extra_field);
            fuzz_monero_transaction_serialize_deserialize(&transaction);
        }
    }

    #[test]
    fn test_fuzz_monero_hash_convert() {
        let mut rng = rand::thread_rng();
        for i in 0..128 {
            let data: Vec<u8> = if i == 0 {
                Vec::new()
            } else {
                (0..i).map(|_| rng.gen()).collect()
            };
            fuzz_monero_hash_convert(&data);
        }
    }

    #[test]
    fn test_fuzz_monero_raw_extra_field_from() {
        let mut rng = rand::thread_rng();
        for i in 0..128 {
            let data: Vec<u8> = if i == 0 {
                Vec::new()
            } else {
                (0..i).map(|_| rng.gen()).collect()
            };
            let extra_field = fuzz_monero_create_extra_field(&data);
            if RawExtraField::try_from(extra_field).is_ok() {};
        }
    }

    #[test]
    fn test_fuzz_monero_raw_extra_field_deserialize() {
        let mut rng = rand::thread_rng();
        for i in 0..128 {
            let data: Vec<u8> = if i == 0 {
                Vec::new()
            } else {
                (0..i).map(|_| rng.gen()).collect()
            };
            let extra_field = fuzz_monero_create_extra_field(&data);
            let raw_extra_field = match RawExtraField::try_from(extra_field) {
                Ok(val) => val,
                Err(_) => {
                    // This may not fail, otherwise the test cannot continue
                    continue;
                },
            };
            fuzz_monero_raw_extra_field_deserialize(&raw_extra_field);
        }
    }

    #[test]
    fn test_fuzz_monero_extra_field_try_parse() {
        let mut rng = rand::thread_rng();
        for i in 0..128 {
            let data: Vec<u8> = if i == 0 {
                Vec::new()
            } else {
                (0..i).map(|_| rng.gen()).collect()
            };
            let extra_field = fuzz_monero_create_extra_field(&data);
            fuzz_monero_extra_field_try_parse(&extra_field);
        }
    }

    #[test]
    fn test_failing_monero_extra_field_try_parse() {
        let data = [];
        let extra_field = fuzz_monero_create_extra_field(&data);
        fuzz_monero_extra_field_try_parse(&extra_field);
        let data = [175, 205, 212, 137, 190, 193, 71, 23];
        let extra_field = fuzz_monero_create_extra_field(&data);
        fuzz_monero_extra_field_try_parse(&extra_field);
        let data = [76, 194, 127, 140, 198, 46, 180, 184, 46, 127, 172, 7, 224, 136, 113, 12, 180, 45, 96, 207, 247, 109, 229, 69, 45, 87, 25, 113, 71, 210, 114, 115];
        let extra_field = fuzz_monero_create_extra_field(&data);
        fuzz_monero_extra_field_try_parse(&extra_field);
        let data = [122, 151, 164, 80, 29, 172, 251, 222, 81, 62, 225, 153, 115, 188, 194, 47, 65, 74, 133, 87, 223, 146, 171, 153, 126, 160, 231, 72, 112, 235, 85, 137, 160, 84, 231, 45, 103, 114, 163, 148, 133, 107, 125, 200, 160, 193, 207, 173, 222, 253, 242, 235, 62, 92, 232, 150, 124, 130, 101, 200, 65, 85, 249, 9];
        let extra_field = fuzz_monero_create_extra_field(&data);
        fuzz_monero_extra_field_try_parse(&extra_field);
    }

    #[test]
    fn test_fuzz_monero_transaction_hash() {
        let mut rng = rand::thread_rng();
        for i in 0..128 {
            let data: Vec<u8> = if i == 0 {
                Vec::new()
            } else {
                (0..i).map(|_| rng.gen()).collect()
            };
            let extra_field = fuzz_monero_create_extra_field(&data);
            let raw_extra_field = match RawExtraField::try_from(extra_field) {
                Ok(val) => val,
                Err(_) => {
                    // This may not fail, otherwise the test cannot continue
                    continue;
                },
            };
            let transaction = fuzz_monero_create_transaction(&data, &raw_extra_field);
            fuzz_monero_transaction_hash(&transaction);
        }
    }

    #[test]
    fn test_fuzz_monero_transaction_check_outputs() {
        let mut rng = rand::thread_rng();
        for i in 0..128 {
            let data: Vec<u8> = if i == 0 {
                Vec::new()
            } else {
                (0..i).map(|_| rng.gen()).collect()
            };
            let extra_field = fuzz_monero_create_extra_field(&data);
            let raw_extra_field = match RawExtraField::try_from(extra_field) {
                Ok(val) => val,
                Err(_) => {
                    // This may not fail, otherwise the test cannot continue
                    continue;
                },
            };
            let transaction = fuzz_monero_create_transaction(&data, &raw_extra_field);
            fuzz_monero_transaction_check_outputs(&transaction);
        }
    }
}
