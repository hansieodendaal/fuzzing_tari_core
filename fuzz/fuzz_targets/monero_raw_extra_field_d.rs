#![no_main]

use libfuzzer_sys::fuzz_target;
use tari_fuzz_lib::monero_fuzz::{
    fuzz_monero_create_extra_field,
    fuzz_monero_raw_extra_field_deserialize,
};
use monero::blockdata::transaction::RawExtraField;

// Note: This fuzz did not panic

fuzz_target!(|data: &[u8]| {
    let extra_field = fuzz_monero_create_extra_field(&data);
    let raw_extra_field = match RawExtraField::try_from(extra_field) {
        Ok(val) => val,
        Err(_) => {
            // This may not fail, otherwise the test cannot continue
            return;
        },
    };
    fuzz_monero_raw_extra_field_deserialize(&raw_extra_field);
});
