#![forbid(unsafe_code)]

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AobPattern {
    pub bytes: Vec<u8>,
    pub mask: Vec<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseAobError {
    InvalidHexToken { token: String },
}

pub fn parse_aob(pattern: &str) -> Result<AobPattern, ParseAobError> {
    let mut bytes = Vec::new();
    let mut mask = Vec::new();

    for token in pattern.split_whitespace() {
        if token == "??" || token == "?" {
            bytes.push(0x00);
            mask.push(false);
            continue;
        }

        let byte = u8::from_str_radix(token, 16).map_err(|_| ParseAobError::InvalidHexToken {
            token: token.to_string(),
        })?;
        bytes.push(byte);
        mask.push(true);
    }

    Ok(AobPattern { bytes, mask })
}

pub fn match_aob(data: &[u8], pattern: &AobPattern) -> Vec<usize> {
    match_aob_limited(data, pattern, usize::MAX)
}

pub fn match_aob_limited(data: &[u8], pattern: &AobPattern, max_results: usize) -> Vec<usize> {
    let pattern_len = pattern.bytes.len();
    if max_results == 0 || pattern_len == 0 || data.len() < pattern_len {
        return Vec::new();
    }

    let mut hits = Vec::new();
    for offset in 0..=(data.len() - pattern_len) {
        let matched = pattern
            .bytes
            .iter()
            .zip(&pattern.mask)
            .enumerate()
            .all(|(idx, (&byte, &must_match))| !must_match || data[offset + idx] == byte);

        if matched {
            hits.push(offset);
            if hits.len() >= max_results {
                break;
            }
        }
    }

    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_literal_and_wildcard_bytes() {
        let pattern = parse_aob("48 8B ?? 44").unwrap();

        assert_eq!(pattern.bytes, vec![0x48, 0x8b, 0x00, 0x44]);
        assert_eq!(pattern.mask, vec![true, true, false, true]);
    }

    #[test]
    fn rejects_invalid_hex_token() {
        let error = parse_aob("48 GG").unwrap_err();

        assert_eq!(
            error,
            ParseAobError::InvalidHexToken {
                token: "GG".to_string(),
            }
        );
    }

    #[test]
    fn matches_literal_pattern_offsets() {
        let pattern = parse_aob("E8 12 34").unwrap();

        assert_eq!(match_aob(&[0x00, 0xe8, 0x12, 0x34], &pattern), vec![1]);
    }

    #[test]
    fn matches_wildcard_pattern_offsets() {
        let pattern = parse_aob("E8 ?? 34").unwrap();

        assert_eq!(
            match_aob(&[0xe8, 0x99, 0x34, 0xe8, 0x12, 0x00], &pattern),
            vec![0]
        );
    }

    #[test]
    fn matches_all_wildcard_windows() {
        let pattern = parse_aob("?? ??").unwrap();

        assert_eq!(match_aob(&[0x01, 0x02, 0x03], &pattern), vec![0, 1]);
    }

    #[test]
    fn empty_pattern_matches_nothing() {
        let pattern = parse_aob("").unwrap();

        assert!(match_aob(&[0x01, 0x02], &pattern).is_empty());
    }

    #[test]
    fn limits_match_results() {
        let pattern = parse_aob("AA").unwrap();

        assert_eq!(
            match_aob_limited(&[0xaa, 0xaa, 0xaa], &pattern, 2),
            vec![0, 1]
        );
    }
}
