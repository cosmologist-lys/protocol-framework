use crate::hex_util;

// 拦截器。如果bytes跟输入值匹配上了，就返回value_if_matches
pub struct DecodingFilter {
    pub(crate) bytes: Vec<u8>,
    pub(crate) value_if_matches: String,
}

impl DecodingFilter {
    pub fn new_from_hex(hex: &str, matched_title: String) -> Self {
        let bytes = hex_util::hex_to_bytes(hex).unwrap();
        DecodingFilter {
            bytes,
            value_if_matches: matched_title,
        }
    }

    pub fn new(bytes: Vec<u8>, matched_title: String) -> Self {
        DecodingFilter {
            bytes,
            value_if_matches: matched_title,
        }
    }

    pub fn matches(&self, input_bytes: &[u8]) -> bool {
        self.bytes == input_bytes
    }

    pub fn matches_hex(&self, input_hex: &str) -> bool {
        let bytes = hex_util::hex_to_bytes(input_hex).unwrap();
        self.matches(&bytes)
    }

    pub fn title(&self) -> String {
        self.value_if_matches.clone()
    }
}
