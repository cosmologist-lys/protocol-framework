// hex + bytes
#[derive(Debug, Clone, Default)]
pub struct TransportPair {
    pub(crate) hex: String,
    pub(crate) bytes: Vec<u8>,
}

impl TransportPair {
    pub fn new(hex: String, bytes: Vec<u8>) -> Self {
        Self { hex, bytes }
    }

    pub fn set_hex(&mut self, hex: &str) {
        self.hex = hex.into();
    }

    pub fn set_bytes(&mut self, bytes: &[u8]) {
        self.bytes = bytes.into();
    }

    // Getter methods
    pub fn hex(&self) -> &str {
        &self.hex
    }

    pub fn hex_clone(&self) -> String {
        self.hex.clone()
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn bytes_clone(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}
