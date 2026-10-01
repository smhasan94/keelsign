//! Fuzz target `parse_image`: `Image::parse`, `Image::read_from` and the TLV iterators
//! against an independent reference parser (`keelsign_fuzz::check_parse_image`).
#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    keelsign_fuzz::check_parse_image(data);
});
