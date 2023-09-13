#![no_main]

use libfuzzer_sys::fuzz_target;
use tari_fuzz_lib::monero_fuzz::fuzz_monero_hash_convert;

// Note: This fuzz did not panic

fuzz_target!(|data: &[u8]| {
    fuzz_monero_hash_convert(data)
});
