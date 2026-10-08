//! Independent master-file TXT decoder for unit/property/fuzz assertions.

/// Decode only the quoted-string grammar emitted by Wardnet, rejecting malformed
/// escapes, unquoted text and character strings exceeding RFC 1035's byte limit.
/// This deliberately does not call the production encoder or share its limits.
pub fn decode_txt_rdata(text: &str) -> Vec<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut offset = 0;
    let mut strings = Vec::new();
    while offset < bytes.len() {
        assert_eq!(bytes[offset], b'"', "TXT string must begin with a quote");
        offset += 1;
        let mut decoded = Vec::new();
        loop {
            let byte = *bytes.get(offset).expect("unterminated TXT string");
            offset += 1;
            match byte {
                b'"' => break,
                b'\\' => {
                    let escaped = *bytes.get(offset).expect("unterminated TXT escape");
                    if escaped.is_ascii_digit() {
                        let digits = bytes.get(offset..offset + 3).expect("short decimal escape");
                        assert!(digits.iter().all(u8::is_ascii_digit));
                        let value = digits
                            .iter()
                            .fold(0u16, |v, d| v * 10 + u16::from(d - b'0'));
                        decoded.push(u8::try_from(value).expect("decimal escape exceeds one byte"));
                        offset += 3;
                    } else {
                        assert!(matches!(escaped, b'"' | b'\\'), "unexpected TXT escape");
                        decoded.push(escaped);
                        offset += 1;
                    }
                }
                b'\n' | b'\r' => panic!("raw line break in TXT string"),
                byte => decoded.push(byte),
            }
        }
        assert!(
            decoded.len() <= 255,
            "TXT character string exceeds 255 bytes: {}",
            decoded.len()
        );
        strings.push(decoded);
        if offset < bytes.len() {
            assert_eq!(bytes[offset], b' ', "TXT strings must be separated");
            offset += 1;
            assert!(offset < bytes.len(), "trailing TXT separator");
        }
    }
    assert!(!strings.is_empty(), "TXT requires a character string");
    strings
}

/// Check every TXT record's grammar and wire-size limits, retaining all bytes
/// for callers that also assert lossless reason/source round trips.
pub fn assert_zone_txt_valid(zone: &str) {
    for line in zone.lines() {
        if let Some((_, text)) = line.split_once(" IN TXT ") {
            let strings = decode_txt_rdata(text);
            assert!(strings.iter().all(|string| string.len() <= 255));
            assert!(
                strings.iter().map(|string| 1 + string.len()).sum::<usize>() <= 65_535,
                "TXT RDATA exceeds the unsigned 16-bit RDLENGTH field"
            );
        }
    }
}
