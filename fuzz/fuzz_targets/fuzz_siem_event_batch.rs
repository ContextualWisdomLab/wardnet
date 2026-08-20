#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use waf_ids_ai_soc::siem_event_input::read_events;

fuzz_target!(|data: &[u8]| {
    let _ = read_events(Cursor::new(data));
});
