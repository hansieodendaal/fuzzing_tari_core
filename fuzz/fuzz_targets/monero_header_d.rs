#![no_main]

use libfuzzer_sys::fuzz_target;
use tari_fuzz_lib::monero_fuzz::fuzz_monero_block_header_deserialize;

// Note: Panicked
//
// thread '<unnamed>' panicked at 'assertion failed: `(left == right)`
//   left: `[240, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 251]`,
//  right: `[112, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 251]`',
//         /mnt/c/Users/pluto/.tari/Code/fuzzing-tari-core/src/monero_fuzz.rs:33:13



fuzz_target!(|data: &[u8]| {
    fuzz_monero_block_header_deserialize(data)
});
