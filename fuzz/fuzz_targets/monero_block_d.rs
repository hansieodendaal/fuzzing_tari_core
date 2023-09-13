#![no_main]

use libfuzzer_sys::fuzz_target;
use tari_fuzz_lib::monero_fuzz::fuzz_monero_block_deserialize;

// Note: Panicked
//
// Failing input:
//
//         fuzz/artifacts/monero_block_d/crash-d6fd68df1309d4704613f5bdbe3f1b6110ad60c4
//
// Output of `std::fmt::Debug`:
//
//         [0, 0, 0, 10, 33, 10, 2, 2, 2, 6, 167, 175, 253, 167, 167, 167, 167, 167, 167, 167, 89, 88, 88, 88, 88, 88, 88, 88, 167, 167, 167, 0, 167, 145, 145, 145, 145, 145, 2, 253, 253, 126, 0, 1, 255, 2, 2, 2, 2, 2, 2, 2, 2, 2, 63, 140, 29, 29, 233, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 3, 3, 3, 3, 3, 2, 63, 140, 29, 29, 233, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29 , 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 0, 0, 0, 0, 0, 0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29]

fuzz_target!(|data: &[u8]| {
    fuzz_monero_block_deserialize(data)
});
