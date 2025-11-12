// 报文帧字段 最小解析单位
#[derive(Debug, Clone, Default)]
pub struct Rawfield {
    pub(crate) bytes: Vec<u8>,
    pub(crate) title: String,
    pub(crate) hex: String,
    pub(crate) value: String,
}

impl Rawfield {
    /// 一个构造函数，用于根据原始字节和翻译结果来创建Rawfield
    pub fn new(raw_bytes: &[u8], title: String, value: String) -> Self {
        Self {
            bytes: raw_bytes.to_vec(),
            title,
            hex: hex::encode_upper(raw_bytes), // 编码为Hex字符串
            value,
        }
    }

    pub fn new_with_hex(hex: &str, title: &str, value: String) -> Self {
        Self {
            bytes: crate::utils::hex_util::hex_to_bytes(hex).unwrap(),
            title: title.into(),
            hex: hex.into(),
            value,
        }
    }

    // pub fn hex_to_bytes(&self) -> crate::defi::ProtocolResult<Vec<u8>> {
    //     crate::utils::hex_util::hex_to_bytes(&self.hex)
    // }

    // Getter methods
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn bytes_clone(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn title_clone(&self) -> String {
        self.title.clone()
    }

    pub fn hex(&self) -> &str {
        &self.hex
    }

    pub fn hex_clone(&self) -> String {
        self.hex.clone()
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn value_clone(&self) -> String {
        self.value.clone()
    }
}
