#![no_main]

use libfuzzer_sys::fuzz_target;
use tari_fuzz_lib::monero_fuzz::{
    fuzz_monero_create_extra_field,
    fuzz_monero_create_transaction,
    fuzz_monero_transaction_serialize_deserialize,
};
use monero::blockdata::transaction::RawExtraField;

// Note: Panicked
//
// thread '<unnamed>' panicked at 'called `Result::unwrap()` on an `Err` value:
// Custom { kind: Interrupted, error: ScriptNotSupported }',
// /home/pluto/.cargo/registry/src/index.crates.io-6f17d22bba15001f/monero-0.18.2/src/consensus/encode.rs:69:51

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    let extra_field = fuzz_monero_create_extra_field(&data);
    let raw_extra_field = match RawExtraField::try_from(extra_field) {
        Ok(val) => val,
        Err(_) => {
            // This may not fail, otherwise the test cannot continue
            return;
        },
    };
    let transaction = fuzz_monero_create_transaction(&data, &raw_extra_field);
    fuzz_monero_transaction_serialize_deserialize(&transaction);
});
