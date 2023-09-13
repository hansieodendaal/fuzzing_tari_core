#![no_main]

use libfuzzer_sys::fuzz_target;
use tari_fuzz_lib::monero_fuzz::{
    fuzz_monero_create_extra_field,
};
use monero::blockdata::transaction::RawExtraField;

// Note: This fuzz did not panic

fuzz_target!(|data: &[u8]| {
    let extra_field = fuzz_monero_create_extra_field(&data);
    if RawExtraField::try_from(extra_field).is_ok() {};
});
