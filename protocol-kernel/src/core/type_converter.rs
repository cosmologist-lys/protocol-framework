use std::fmt::Display;
use std::marker::PhantomData;

use crate::math_util::{self, DecimalRoundingMode};
use crate::{
    ProtocolError, ProtocolResult, Rawfield, Symbol, handle_int, handle_int_encode, hex_util,
};

#[derive(Debug, Clone)]
/// 字段类型
pub enum FieldType {
    Empty,
    StringOrBCD,      // 文字 or BCD
    UnsignedU8(f64),  // 正整数(缩小倍数) 1
    UnsignedU16(f64), // 正整数(缩小倍数) 2
    UnsignedU32(f64), // 正整数(缩小倍数) 3
    UnsignedU64(f64), // 正整数(缩小倍数) 4
    SignedI8(f64),    // 正负整数(缩小倍数) 1
    SignedI16(f64),   // 正负整数(缩小倍数) 2
    SignedI32(f64),   // 正负整数(缩小倍数) 3
    SignedI64(f64),   // 正负整数(缩小倍数) 4
    Float,            // 单精度4字节
    Double,           // 双精度8字节
    Ascii,            // ascii
}

impl PartialEq for FieldType {
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

impl FieldType {
    /// 根据FieldType将大端字节切片转换为字符串表示。 上行解码
    pub fn decode(&self, bytes: &[u8]) -> ProtocolResult<String> {
        match self {
            FieldType::Empty => Ok("".to_string()),
            FieldType::StringOrBCD => hex_util::bytes_to_hex(bytes),
            FieldType::UnsignedU8(scale) => handle_int!(u8, 1, bytes, *scale),
            FieldType::UnsignedU16(scale) => handle_int!(u16, 2, bytes, *scale),
            FieldType::UnsignedU32(scale) => handle_int!(u32, 4, bytes, *scale),
            FieldType::UnsignedU64(scale) => handle_int!(u64, 8, bytes, *scale),
            FieldType::SignedI8(scale) => handle_int!(i8, 1, bytes, *scale),
            FieldType::SignedI16(scale) => handle_int!(i16, 2, bytes, *scale),
            FieldType::SignedI32(scale) => handle_int!(i32, 4, bytes, *scale),
            FieldType::SignedI64(scale) => handle_int!(i64, 8, bytes, *scale),
            FieldType::Float => {
                if bytes.len() != 4 {
                    return Err(ProtocolError::ValidationFailed(format!(
                        "Invalid byte length for Float. Expected 4, got {}",
                        bytes.len()
                    )));
                }
                let value = f32::from_be_bytes(bytes.try_into().unwrap());
                Ok(value.to_string())
            }
            FieldType::Double => {
                if bytes.len() != 8 {
                    return Err(ProtocolError::ValidationFailed(format!(
                        "Invalid byte length for Double. Expected 8, got {}",
                        bytes.len()
                    )));
                }
                let value = f64::from_be_bytes(bytes.try_into().unwrap());
                Ok(value.to_string())
            }
            FieldType::Ascii => {
                // 检查是否所有字节都是ASCII
                if !bytes.is_ascii() {
                    return Err(ProtocolError::CommonError(
                        "Input bytes are not valid ASCII".to_string(),
                    ));
                }
                // 安全地将ASCII字节转换为String (不会失败)
                Ok(String::from_utf8(bytes.to_vec()).unwrap())
            }
        }
    }

    // 下行编码
    pub fn encode(&self, input: &str) -> ProtocolResult<Vec<u8>> {
        match self {
            FieldType::Empty => Ok(vec![]),
            FieldType::StringOrBCD => {
                let bytes = hex_util::hex_to_bytes(input)?;
                Ok(bytes)
            }
            FieldType::UnsignedU8(scale) => handle_int_encode!(u8, 1, input, *scale),
            FieldType::UnsignedU16(scale) => handle_int_encode!(u16, 2, input, *scale),
            FieldType::UnsignedU32(scale) => handle_int_encode!(u32, 4, input, *scale),
            FieldType::UnsignedU64(scale) => handle_int_encode!(u64, 8, input, *scale),
            FieldType::SignedI8(scale) => handle_int_encode!(i8, 1, input, *scale),
            FieldType::SignedI16(scale) => handle_int_encode!(i16, 2, input, *scale),
            FieldType::SignedI32(scale) => handle_int_encode!(i32, 4, input, *scale),
            FieldType::SignedI64(scale) => handle_int_encode!(i64, 8, input, *scale),
            FieldType::Float => {
                let value: f32 = input.parse().map_err(|_| {
                    ProtocolError::ValidationFailed(format!(
                        "Failed to parse input '{}' as f32",
                        input
                    ))
                })?;
                let bytes = value.to_be_bytes();
                Ok(bytes.to_vec())
            }
            FieldType::Double => {
                let value: f64 = input.parse().map_err(|_| {
                    ProtocolError::ValidationFailed(format!(
                        "Failed to parse input '{}' as f64",
                        input
                    ))
                })?;
                let bytes = value.to_be_bytes();
                Ok(bytes.to_vec())
            }
            FieldType::Ascii => {
                // 检查输入是否只包含ASCII字符
                if !input.is_ascii() {
                    return Err(ProtocolError::CommonError(
                        "Input string contains non-ASCII characters".to_string(),
                    ));
                }
                let bytes = input.as_bytes().to_vec();
                Ok(bytes)
            }
        }
    }
}
// 单个帧字段的翻译: 翻译模式
#[derive(Debug, Clone)]
pub struct FieldConvertDecoder {
    pub title: String,         // 标题
    pub swap: bool,            // 是否高低换位，或true=小端 false=大端
    pub filed_type: FieldType, // 帧字段类型 不为空即是: 翻译模式。
    // 翻译之后的符号
    pub symbol: Option<Symbol>,
}

#[derive(Debug, Clone)]
// 单个帧字段的翻译：比较模式
pub struct FieldCompareDecoder {
    pub title: String,           // 标题
    pub swap: bool,              // 是否高低换位，或true=小端 false=大端
    pub compare_target: Vec<u8>, // 比较目标 不为空即是：比较模式
}

#[derive(Debug, Clone)]
pub struct FieldEnumDecoder<T: TryFromBytes> {
    // 添加泛型参数 T 和 Trait Bound
    pub title: String,
    pub swap: bool,
    pub enum_values: Vec<(T, String)>, // 键的类型现在是 T
    _marker: PhantomData<T>,           // 因为 T 没有直接用在字段中，需要 PhantomData
}

impl FieldConvertDecoder {
    pub fn new(title: &str, filed_type: FieldType, symbol: Option<Symbol>, swap: bool) -> Self {
        FieldConvertDecoder {
            title: title.to_string(),
            filed_type,
            swap,
            symbol,
        }
    }

    pub fn set_symbol(&mut self, symbol: Symbol) {
        self.symbol = Some(symbol);
    }
}

impl FieldCompareDecoder {
    pub fn new(title: &str, compare_target: Vec<u8>, swap: bool) -> Self {
        FieldCompareDecoder {
            title: title.to_string(),
            compare_target,
            swap,
        }
    }
}

// 您可能需要一个构造函数
impl<T: TryFromBytes> FieldEnumDecoder<T> {
    pub fn new(title: &str, enum_values: Vec<(T, String)>, swap: bool) -> Self {
        Self {
            title: title.to_string(),
            swap,
            enum_values,
            _marker: PhantomData,
        }
    }
}
pub trait SingleFieldDecode {
    fn swap(&self) -> bool;
    fn title(&self) -> &str;
}

impl SingleFieldDecode for FieldCompareDecoder {
    fn swap(&self) -> bool {
        self.swap
    }
    fn title(&self) -> &str {
        &self.title
    }
}

impl SingleFieldDecode for FieldConvertDecoder {
    fn swap(&self) -> bool {
        self.swap
    }
    fn title(&self) -> &str {
        &self.title
    }
}

impl<T: TryFromBytes> SingleFieldDecode for FieldEnumDecoder<T> {
    fn swap(&self) -> bool {
        self.swap
    }
    fn title(&self) -> &str {
        &self.title
    }
}

pub trait FieldTranslator {
    fn translate(&self, bytes: &[u8]) -> ProtocolResult<Rawfield>;
}

impl FieldTranslator for FieldConvertDecoder {
    fn translate(&self, bytes: &[u8]) -> ProtocolResult<Rawfield> {
        let mut copied_bytes = bytes.to_vec(); // 替代 clone_from_slice，更简单
        let input_bytes = if self.swap && bytes.len() > 1 {
            copied_bytes.reverse();
            copied_bytes
        } else {
            copied_bytes
        };
        let ft = &self.filed_type;
        let mut value = ft.decode(&input_bytes)?;
        // 如果有符号，拼接上去
        if self.symbol.is_some() {
            let symbol_some_clone = self.symbol.clone();
            let symbol = symbol_some_clone.unwrap();
            value += " ";
            value += symbol.tag().as_str();
        }
        Ok(Rawfield::new(bytes, self.title.clone(), value))
    }
}

impl FieldTranslator for FieldCompareDecoder {
    fn translate(&self, bytes: &[u8]) -> ProtocolResult<Rawfield> {
        let mut copied_bytes = bytes.to_vec(); // 替代 clone_from_slice，更简单
        let input_bytes = if self.swap && bytes.len() > 1 {
            copied_bytes.reverse();
            copied_bytes
        } else {
            copied_bytes
        };

        if input_bytes != self.compare_target {
            return Err(ProtocolError::CommonError(format!(
                "compare failed , target bytes : {:?} , expected bytes : {:?}",
                input_bytes, self.compare_target
            )));
        }
        let hex = hex_util::bytes_to_hex(&input_bytes)?;

        let rf = Rawfield::new(bytes, self.title.clone(), hex);

        Ok(rf)
    }
}

impl<T: TryFromBytes> FieldTranslator for FieldEnumDecoder<T> {
    fn translate(&self, bytes: &[u8]) -> ProtocolResult<Rawfield> {
        // 1. 使用 TryFromBytes Trait 将字节转换为泛型类型 T
        let key_value: T = T::try_from_bytes(bytes, self.swap)?;

        // 2. 在 Vec<(T, String)> 中查找匹配的键
        let value_str = self
            .enum_values
            .iter()
            // 使用 PartialEq 来比较 T == T
            .find(|(enum_key, _)| *enum_key == key_value)
            // 如果找到，返回对应的 String 值
            .map(|(_, enum_value)| enum_value.clone())
            // 如果未找到，使用 T 的 Display 实现作为默认值
            .unwrap_or_else(|| key_value.to_string());

        // 3. 构建 Rawfield
        let rf = Rawfield::new(bytes, self.title.clone(), value_str);
        Ok(rf)
    }
}
/// 一个 trait，用于尝试从字节切片（考虑字节序）转换为目标类型 T。
pub trait TryFromBytes: Sized + PartialEq + Display + Clone {
    // Sized: 类型大小在编译时已知
    // PartialEq: 可以进行比较 (==)
    // Display: 可以转换为字符串 (用于未找到匹配时的默认值)
    // Clone: 方便在 Vec<(T, String)> 中存储和比较

    /// 尝试从字节切片转换。
    /// bytes: 输入的字节切片。
    /// swap: 是否需要反转字节序（true=小端，false=大端）。
    fn try_from_bytes(bytes: &[u8], swap: bool) -> ProtocolResult<Self>;
}

impl TryFromBytes for u8 {
    fn try_from_bytes(bytes: &[u8], _swap: bool) -> ProtocolResult<Self> {
        if bytes.len() != 1 {
            return Err(ProtocolError::ValidationFailed(format!(
                "Invalid byte length for u8. Expected 1, got {}",
                bytes.len()
            )));
        }
        // u8 不受字节序影响
        Ok(bytes[0])
    }
}

impl TryFromBytes for i8 {
    fn try_from_bytes(bytes: &[u8], _swap: bool) -> ProtocolResult<Self> {
        if bytes.len() != 1 {
            return Err(ProtocolError::ValidationFailed(format!(
                "Invalid byte length for i8. Expected 1, got {}",
                bytes.len()
            )));
        }
        // u8 不受字节序影响
        Ok(bytes[0] as i8)
    }
}

impl TryFromBytes for u16 {
    fn try_from_bytes(bytes: &[u8], swap: bool) -> ProtocolResult<Self> {
        if bytes.len() != 2 {
            return Err(ProtocolError::ValidationFailed(format!(
                "Invalid byte length for u16. Expected 2, got {}",
                bytes.len()
            )));
        }
        let arr: [u8; 2] = bytes.try_into().unwrap(); // 安全，已检查长度
        if swap {
            // 小端
            Ok(u16::from_le_bytes(arr))
        } else {
            // 大端
            Ok(u16::from_be_bytes(arr))
        }
    }
}

impl TryFromBytes for i16 {
    fn try_from_bytes(bytes: &[u8], swap: bool) -> ProtocolResult<Self> {
        if bytes.len() != 2 {
            return Err(ProtocolError::ValidationFailed(format!(
                "Invalid byte length for i16. Expected 2, got {}",
                bytes.len()
            )));
        }
        let arr: [u8; 2] = bytes.try_into().unwrap();
        if swap {
            // 小端
            Ok(i16::from_le_bytes(arr))
        } else {
            // 大端
            Ok(i16::from_be_bytes(arr))
        }
    }
}

impl TryFromBytes for u32 {
    fn try_from_bytes(bytes: &[u8], swap: bool) -> ProtocolResult<Self> {
        if bytes.len() != 4 {
            return Err(ProtocolError::ValidationFailed(format!(
                "Invalid byte length for u16. Expected 2, got {}",
                bytes.len()
            )));
        }
        let arr: [u8; 4] = bytes.try_into().unwrap(); // 安全，已检查长度
        if swap {
            // 小端
            Ok(u32::from_le_bytes(arr))
        } else {
            // 大端
            Ok(u32::from_be_bytes(arr))
        }
    }
}

impl TryFromBytes for i32 {
    fn try_from_bytes(bytes: &[u8], swap: bool) -> ProtocolResult<Self> {
        if bytes.len() != 4 {
            return Err(ProtocolError::ValidationFailed(format!(
                "Invalid byte length for u16. Expected 2, got {}",
                bytes.len()
            )));
        }
        let arr: [u8; 4] = bytes.try_into().unwrap(); // 安全，已检查长度
        if swap {
            // 小端
            Ok(i32::from_le_bytes(arr))
        } else {
            // 大端
            Ok(i32::from_be_bytes(arr))
        }
    }
}

impl TryFromBytes for u64 {
    fn try_from_bytes(bytes: &[u8], swap: bool) -> ProtocolResult<Self> {
        if bytes.len() != 8 {
            return Err(ProtocolError::ValidationFailed(format!(
                "Invalid byte length for u16. Expected 2, got {}",
                bytes.len()
            )));
        }
        let arr: [u8; 8] = bytes.try_into().unwrap(); // 安全，已检查长度
        if swap {
            // 小端
            Ok(u64::from_le_bytes(arr))
        } else {
            // 大端
            Ok(u64::from_be_bytes(arr))
        }
    }
}

impl TryFromBytes for i64 {
    fn try_from_bytes(bytes: &[u8], swap: bool) -> ProtocolResult<Self> {
        if bytes.len() != 8 {
            return Err(ProtocolError::ValidationFailed(format!(
                "Invalid byte length for u16. Expected 2, got {}",
                bytes.len()
            )));
        }
        let arr: [u8; 8] = bytes.try_into().unwrap(); // 安全，已检查长度
        if swap {
            // 小端
            Ok(i64::from_le_bytes(arr))
        } else {
            // 大端
            Ok(i64::from_be_bytes(arr))
        }
    }
}

impl TryFromBytes for String {
    /// 将字节切片转换为大写的 Hex 字符串。
    fn try_from_bytes(bytes: &[u8], swap: bool) -> ProtocolResult<Self> {
        if swap {
            hex_util::bytes_to_hex_swap(bytes)
        } else {
            hex_util::bytes_to_hex(bytes)
        }
    }
}
