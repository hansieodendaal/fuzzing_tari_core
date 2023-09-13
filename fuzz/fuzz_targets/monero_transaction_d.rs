#![no_main]

use libfuzzer_sys::fuzz_target;
use tari_fuzz_lib::monero_fuzz::fuzz_monero_transaction_deserialize;

// Note: Panicked
//
// thread '<unnamed>' panicked at 'assertion failed: `(left == right)`
//   left: `[1, 188, 0, 0, 0, 0]`,
//  right: `[1, 60, 0, 0, 0]`',
//         /mnt/c/Users/pluto/.tari/Code/fuzzing-tari-core/src/monero_fuzz.rs:65:13

fuzz_target!(|data: &[u8]| {
    fuzz_monero_transaction_deserialize(data)
});
