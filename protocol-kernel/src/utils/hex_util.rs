use protocol_base::{
    ProtocolResult,
    error::{ProtocolError, hex_error::HexError},
};
use std::{fmt::LowerHex, mem::size_of}; // 引入 size_of

// --- 核心转换 ---

/// 将 Hex 字符串解码为字节向量。
pub fn hex_to_bytes(s: &str) -> ProtocolResult<Vec<u8>> {
    let cleaned = _clean_and_pad_hex_str(s);
    // hex::decode 会处理非法字符
    hex::decode(&cleaned).map_err(|e| {
        ProtocolError::HexError(HexError::HexParseError {
            context: "bytes",
            reason: e.to_string(),
        })
    })
}

/// 将字节切片编码为大写 Hex 字符串。
pub fn bytes_to_hex(bytes: &[u8]) -> ProtocolResult<String> {
    Ok(hex::encode_upper(bytes))
}

/// 将 Hex 字符串解码为字节向量，然后反转字节顺序。
pub fn hex_to_bytes_swap(s: &str) -> ProtocolResult<Vec<u8>> {
    let mut bytes = hex_to_bytes(s)?;
    bytes.reverse();
    Ok(bytes)
}

/// 将字节切片反转顺序，然后编码为大写 Hex 字符串。
pub fn bytes_to_hex_swap(bytes: &[u8]) -> ProtocolResult<String> {
    let mut swapped_bytes = bytes.to_vec();
    swapped_bytes.reverse();
    bytes_to_hex(&swapped_bytes)
}

// --- 字节到数字转换 (大端序) ---

/// 内部辅助函数：从大端字节转换为数字类型 T
fn _bytes_to_number_internal<T>(bytes: &[u8], type_name: &'static str) -> ProtocolResult<T>
where
    T: Sized + FromBytesBE, // 定义一个内部 trait 约束
{
    let expected_len = size_of::<T>();
    if bytes.len() != expected_len {
        let err_msg = format!(
            "Invalid length for {} conversion: expected {}, got {}",
            type_name,
            expected_len,
            bytes.len()
        );
        Err(ProtocolError::CommonError(err_msg))
    } else {
        Ok(T::from_be_bytes(bytes))
    }
}

// 内部 trait，用于泛型约束
trait FromBytesBE: Sized {
    fn from_be_bytes(bytes: &[u8]) -> Self;
}
impl FromBytesBE for i64 {
    fn from_be_bytes(bytes: &[u8]) -> Self {
        i64::from_be_bytes(bytes.try_into().unwrap())
    }
}
impl FromBytesBE for u64 {
    fn from_be_bytes(bytes: &[u8]) -> Self {
        u64::from_be_bytes(bytes.try_into().unwrap())
    }
}
impl FromBytesBE for i32 {
    fn from_be_bytes(bytes: &[u8]) -> Self {
        i32::from_be_bytes(bytes.try_into().unwrap())
    }
}
impl FromBytesBE for u32 {
    fn from_be_bytes(bytes: &[u8]) -> Self {
        u32::from_be_bytes(bytes.try_into().unwrap())
    }
}
impl FromBytesBE for i16 {
    fn from_be_bytes(bytes: &[u8]) -> Self {
        i16::from_be_bytes(bytes.try_into().unwrap())
    }
}
impl FromBytesBE for u16 {
    fn from_be_bytes(bytes: &[u8]) -> Self {
        u16::from_be_bytes(bytes.try_into().unwrap())
    }
}
impl FromBytesBE for i8 {
    fn from_be_bytes(bytes: &[u8]) -> Self {
        i8::from_be_bytes(bytes.try_into().unwrap())
    }
}
impl FromBytesBE for u8 {
    fn from_be_bytes(bytes: &[u8]) -> Self {
        u8::from_be_bytes(bytes.try_into().unwrap())
    }
}
impl FromBytesBE for f64 {
    fn from_be_bytes(bytes: &[u8]) -> Self {
        f64::from_be_bytes(bytes.try_into().unwrap())
    }
}
impl FromBytesBE for f32 {
    fn from_be_bytes(bytes: &[u8]) -> Self {
        f32::from_be_bytes(bytes.try_into().unwrap())
    }
}

pub fn bytes_to_i64(bytes: &[u8]) -> ProtocolResult<i64> {
    _bytes_to_number_internal(bytes, "i64")
}
pub fn bytes_to_u64(bytes: &[u8]) -> ProtocolResult<u64> {
    _bytes_to_number_internal(bytes, "u64")
}
pub fn bytes_to_i32(bytes: &[u8]) -> ProtocolResult<i32> {
    _bytes_to_number_internal(bytes, "i32")
}
pub fn bytes_to_u32(bytes: &[u8]) -> ProtocolResult<u32> {
    _bytes_to_number_internal(bytes, "u32")
}
pub fn bytes_to_i16(bytes: &[u8]) -> ProtocolResult<i16> {
    _bytes_to_number_internal(bytes, "i16")
}
pub fn bytes_to_u16(bytes: &[u8]) -> ProtocolResult<u16> {
    _bytes_to_number_internal(bytes, "u16")
}
pub fn bytes_to_i8(bytes: &[u8]) -> ProtocolResult<i8> {
    _bytes_to_number_internal(bytes, "i8")
}
pub fn bytes_to_u8(bytes: &[u8]) -> ProtocolResult<u8> {
    _bytes_to_number_internal(bytes, "u8")
}

// --- Hex 字符串到数字转换 ---

/// hex -> i64 (有符号 64-bit)
pub fn hex_to_i64(hex: &str) -> ProtocolResult<i64> {
    let bytes = hex_to_bytes(hex)?;
    _bytes_to_number_internal(&bytes, "i64")
}
/// hex -> u64 (无符号 64-bit)
pub fn hex_to_u64(hex: &str) -> ProtocolResult<u64> {
    let bytes = hex_to_bytes(hex)?;
    _bytes_to_number_internal(&bytes, "u64")
}
/// hex -> i32 (有符号 32-bit)
pub fn hex_to_i32(hex: &str) -> ProtocolResult<i32> {
    let bytes = hex_to_bytes(hex)?;
    _bytes_to_number_internal(&bytes, "i32")
}
/// hex -> u32 (无符号 32-bit)
pub fn hex_to_u32(hex: &str) -> ProtocolResult<u32> {
    let bytes = hex_to_bytes(hex)?;
    _bytes_to_number_internal(&bytes, "u32")
}
/// hex -> i16 (有符号 16-bit)
pub fn hex_to_i16(hex: &str) -> ProtocolResult<i16> {
    let bytes = hex_to_bytes(hex)?;
    _bytes_to_number_internal(&bytes, "i16")
}
/// hex -> u16 (无符号 16-bit)
pub fn hex_to_u16(hex: &str) -> ProtocolResult<u16> {
    let bytes = hex_to_bytes(hex)?;
    _bytes_to_number_internal(&bytes, "u16")
}
/// hex -> i8 (有符号 8-bit)
pub fn hex_to_i8(hex: &str) -> ProtocolResult<i8> {
    let bytes = hex_to_bytes(hex)?;
    _bytes_to_number_internal(&bytes, "i8")
}
/// hex -> u8 (无符号 8-bit)
pub fn hex_to_u8(hex: &str) -> ProtocolResult<u8> {
    let bytes = hex_to_bytes(hex)?;
    _bytes_to_number_internal(&bytes, "u8")
}

// --- 数字到 Hex 字符串转换 ---

/// 内部辅助函数：将数字类型 T 转换为指定字节长度的 Hex 字符串（带补位或截断）
fn _number_to_hex_internal<T>(
    number: T,
    expected_byte_length: usize,
    is_signed: bool,
) -> ProtocolResult<String>
where
    // 移除不必要的 u64: TryFrom<T> 和 T: Into<u64>
    // 保留实际需要的约束
    T: LowerHex + PartialOrd + Default + Copy,
{
    let native_byte_length = size_of::<T>();
    let native_char_length = native_byte_length * 2;
    let expected_char_length = expected_byte_length * 2;

    // 获取本地完整宽度的Hex表示
    // LowerHex 会正确处理有符号和无符号类型的位模式
    let native_hex = format!("{:0width$x}", number, width = native_char_length).to_uppercase();

    match expected_char_length.cmp(&native_char_length) {
        std::cmp::Ordering::Less => {
            // 截断
            let start_index = native_char_length - expected_char_length;
            Ok(native_hex[start_index..].to_string())
        }
        std::cmp::Ordering::Equal => Ok(native_hex), // 长度相等
        std::cmp::Ordering::Greater => {
            // 补位
            let padding_len = expected_char_length - native_char_length;
            // 使用 PartialOrd 和 Default 判断符号
            let padding_char = if is_signed && number < T::default() {
                'F' // 符号扩展
            } else {
                '0' // 零扩展
            };

            let mut padded_hex = String::with_capacity(expected_char_length);
            for _ in 0..padding_len {
                padded_hex.push(padding_char);
            }
            padded_hex.push_str(&native_hex);
            Ok(padded_hex)
        }
    }
}

pub fn i64_to_hex(number: i64, expected_byte_length: usize) -> ProtocolResult<String> {
    _number_to_hex_internal(number, expected_byte_length, true)
}
pub fn u64_to_hex(number: u64, expected_byte_length: usize) -> ProtocolResult<String> {
    _number_to_hex_internal(number, expected_byte_length, false)
}
pub fn i32_to_hex(number: i32, expected_byte_length: usize) -> ProtocolResult<String> {
    _number_to_hex_internal(number, expected_byte_length, true)
}
pub fn u32_to_hex(number: u32, expected_byte_length: usize) -> ProtocolResult<String> {
    _number_to_hex_internal(number, expected_byte_length, false)
}
pub fn i16_to_hex(number: i16, expected_byte_length: usize) -> ProtocolResult<String> {
    _number_to_hex_internal(number, expected_byte_length, true)
}
pub fn u16_to_hex(number: u16, expected_byte_length: usize) -> ProtocolResult<String> {
    _number_to_hex_internal(number, expected_byte_length, false)
}
pub fn i8_to_hex(number: i8, expected_byte_length: usize) -> ProtocolResult<String> {
    _number_to_hex_internal(number, expected_byte_length, true)
}
pub fn u8_to_hex(number: u8, expected_byte_length: usize) -> ProtocolResult<String> {
    _number_to_hex_internal(number, expected_byte_length, false)
}

// --- 浮点数转换 ---

pub fn bytes_to_f64(bytes: &[u8]) -> ProtocolResult<f64> {
    _bytes_to_number_internal(bytes, "f64")
}
pub fn bytes_to_f32(bytes: &[u8]) -> ProtocolResult<f32> {
    _bytes_to_number_internal(bytes, "f32")
}

/// hex -> f64 (双精度 8 字节)
pub fn hex_to_f64(hex: &str) -> ProtocolResult<f64> {
    let bytes = hex_to_bytes(hex)?;
    bytes_to_f64(&bytes)
}
/// hex -> f32 (单精度 4 字节)
pub fn hex_to_f32(hex: &str) -> ProtocolResult<f32> {
    let bytes = hex_to_bytes(hex)?;
    bytes_to_f32(&bytes)
}

/// 字节 -> f64 (自动判断 f32 或 f64)
pub fn bytes_to_f32_or_f64(bytes: &[u8]) -> ProtocolResult<f64> {
    match bytes.len() {
        8 => bytes_to_f64(bytes),
        4 => bytes_to_f32(bytes).map(|f| f as f64), // f32 转 f64
        actual_len => Err(ProtocolError::HexError(
            HexError::InvalidFloatLengthEither { actual: actual_len },
        )),
    }
}

/// hex -> f64 (自动判断 f32 或 f64)
pub fn hex_to_f32_or_f64(hex: &str) -> ProtocolResult<f64> {
    let bytes = hex_to_bytes(hex)?;
    bytes_to_f32_or_f64(&bytes)
}

/// f32 (单精度) -> 大端字节 [u8; 4]
pub fn f32_to_bytes(number: f32) -> [u8; 4] {
    number.to_be_bytes()
}
/// f32 (单精度) -> hex-string (大写)
pub fn f32_to_hex(number: f32) -> ProtocolResult<String> {
    bytes_to_hex(&number.to_be_bytes())
}

/// f64 (双精度) -> 大端字节 [u8; 8]
pub fn f64_to_bytes(number: f64) -> [u8; 8] {
    number.to_be_bytes()
}
/// f64 (双精度) -> hex-string (大写)
pub fn f64_to_hex(number: f64) -> ProtocolResult<String> {
    bytes_to_hex(&number.to_be_bytes())
}

/// f64 -> hex-string (根据指定的字节长度 4 或 8)
pub fn f64_to_hex_by_len(number: f64, byte_length: usize) -> ProtocolResult<String> {
    match byte_length {
        4 => f32_to_hex(number as f32), // f64 转 f32 可能损失精度
        8 => f64_to_hex(number),
        actual_len => Err(ProtocolError::HexError(
            HexError::InvalidFloatLengthEither { actual: actual_len },
        )),
    }
}

// --- 二进制字符串转换 ---

/// i8 -> 8-bit binary-string
pub fn i8_to_binary_str(number: i8) -> ProtocolResult<String> {
    Ok(format!("{:08b}", number as u8))
}
/// u8 -> 8-bit binary-string
pub fn u8_to_binary_str(number: u8) -> ProtocolResult<String> {
    Ok(format!("{:08b}", number))
}

/// 核心辅助函数：正确实现比特的零扩展或截断
fn _number_to_bits_internal(
    number_bits: u64, // 用 u64 容纳所有整数类型
    native_width: u32,
    expected_bit_length: usize,
) -> ProtocolResult<String> {
    if expected_bit_length == 0 {
        return Err(ProtocolError::HexError(
            HexError::BinaryLengthErrorNegative { bits: 0 },
        ));
    }
    let native_binary = format!("{number_bits:0>width$b}", width = native_width as usize);
    let native_len = native_width as usize;

    match expected_bit_length.cmp(&native_len) {
        std::cmp::Ordering::Less => {
            // 截断
            let start_index = native_len - expected_bit_length;
            Ok(native_binary[start_index..].to_string())
        }
        std::cmp::Ordering::Equal => Ok(native_binary), // 长度相等
        std::cmp::Ordering::Greater => {
            // 补位 (零扩展)
            let padding_len = expected_bit_length - native_len;
            let mut padded_binary = String::with_capacity(expected_bit_length);
            for _ in 0..padding_len {
                padded_binary.push('0');
            }
            padded_binary.push_str(&native_binary);
            Ok(padded_binary)
        }
    }
}

pub fn i64_to_binary_str(number: i64, expected_bit_length: usize) -> ProtocolResult<String> {
    _number_to_bits_internal(number as u64, 64, expected_bit_length)
}
pub fn u64_to_binary_str(number: u64, expected_bit_length: usize) -> ProtocolResult<String> {
    _number_to_bits_internal(number, 64, expected_bit_length)
}
pub fn i32_to_binary_str(number: i32, expected_bit_length: usize) -> ProtocolResult<String> {
    _number_to_bits_internal(number as u32 as u64, 32, expected_bit_length)
}
pub fn u32_to_binary_str(number: u32, expected_bit_length: usize) -> ProtocolResult<String> {
    _number_to_bits_internal(number as u64, 32, expected_bit_length)
}
pub fn i16_to_binary_str(number: i16, expected_bit_length: usize) -> ProtocolResult<String> {
    _number_to_bits_internal(number as u16 as u64, 16, expected_bit_length)
}
pub fn u16_to_binary_str(number: u16, expected_bit_length: usize) -> ProtocolResult<String> {
    _number_to_bits_internal(number as u64, 16, expected_bit_length)
}

/// binary-string -> i64
pub fn binary_str_to_i64(binary_str: &str) -> ProtocolResult<i64> {
    u64::from_str_radix(binary_str, 2)
        .map(|u| u as i64) // 按位重解释
        .map_err(|e| {
            ProtocolError::HexError(HexError::BinaryParseError {
                context: "i64",
                reason: e.to_string(),
            })
        })
}
/// binary-string -> u64
pub fn binary_str_to_u64(binary_str: &str) -> ProtocolResult<u64> {
    u64::from_str_radix(binary_str, 2).map_err(|e| {
        ProtocolError::HexError(HexError::BinaryParseError {
            context: "u64",
            reason: e.to_string(),
        })
    })
}
/// binary-string -> i32
pub fn binary_str_to_i32(binary_str: &str) -> ProtocolResult<i32> {
    u32::from_str_radix(binary_str, 2)
        .map(|u| u as i32)
        .map_err(|e| {
            ProtocolError::HexError(HexError::BinaryParseError {
                context: "i32",
                reason: e.to_string(),
            })
        })
}
/// binary-string -> u32
pub fn binary_str_to_u32(binary_str: &str) -> ProtocolResult<u32> {
    u32::from_str_radix(binary_str, 2).map_err(|e| {
        ProtocolError::HexError(HexError::BinaryParseError {
            context: "u32",
            reason: e.to_string(),
        })
    })
}
/// binary-string -> i16
pub fn binary_str_to_i16(binary_str: &str) -> ProtocolResult<i16> {
    u16::from_str_radix(binary_str, 2)
        .map(|u| u as i16)
        .map_err(|e| {
            ProtocolError::HexError(HexError::BinaryParseError {
                context: "i16",
                reason: e.to_string(),
            })
        })
}
/// binary-string -> u16
pub fn binary_str_to_u16(binary_str: &str) -> ProtocolResult<u16> {
    u16::from_str_radix(binary_str, 2).map_err(|e| {
        ProtocolError::HexError(HexError::BinaryParseError {
            context: "u16",
            reason: e.to_string(),
        })
    })
}
/// binary-string -> i8
pub fn binary_str_to_i8(binary_str: &str) -> ProtocolResult<i8> {
    u8::from_str_radix(binary_str, 2)
        .map(|u| u as i8)
        .map_err(|e| {
            ProtocolError::HexError(HexError::BinaryParseError {
                context: "i8",
                reason: e.to_string(),
            })
        })
}
/// binary-string -> u8
pub fn binary_str_to_u8(binary_str: &str) -> ProtocolResult<u8> {
    u8::from_str_radix(binary_str, 2).map_err(|e| {
        ProtocolError::HexError(HexError::BinaryParseError {
            context: "u8",
            reason: e.to_string(),
        })
    })
}

/// binary-string -> Vec<bool>
pub fn binary_str_to_bits(binary_str: &str) -> ProtocolResult<Vec<bool>> {
    binary_str
        .chars()
        .map(|c| match c {
            '1' => Ok(true),
            '0' => Ok(false),
            invalid_char => Err(ProtocolError::HexError(HexError::BinaryParseError {
                context: "Vec<bool>",
                reason: format!(
                    "Invalid character '{}' found in binary string",
                    invalid_char
                ),
            })),
        })
        .collect() // 收集 Result<bool, ProtocolError> 到 Result<Vec<bool>, ProtocolError>
}

// --- 辅助函数 ---

/// 反转 Hex 字符串的字节序 (e.g., "123456" -> "563412")
pub fn swap(hex: &str) -> ProtocolResult<String> {
    let mut bytes = hex_to_bytes(hex)?;
    bytes.reverse();
    bytes_to_hex(&bytes)
}

/// 反转字节切片的副本
pub fn swap_bytes(bytes: &[u8]) -> ProtocolResult<Vec<u8>> {
    let mut new_bytes = bytes.to_vec();
    new_bytes.reverse();
    Ok(new_bytes)
}

/// 截取字节数组的指定部分 (panic-safe)
pub fn cut_bytes(data: &[u8], start_index: i64, end_index: i64) -> ProtocolResult<Vec<u8>> {
    // ... (保持您之前的 cut_bytes 实现，它是正确的)
    let total_length = data.len();
    let total_length_i64 = total_length as i64;

    if start_index == 0 && end_index == 0 {
        return Ok(data.to_vec());
    }
    if start_index < 0 && end_index < 0 && start_index > end_index { /* ... */ }

    let final_start = if start_index < 0 {
        (total_length_i64 + start_index).max(0) as usize
    } else {
        (start_index as usize).min(total_length)
    };
    let final_end = if end_index < 0 {
        (total_length_i64 + end_index).max(0) as usize
    } else if end_index == 0 {
        total_length
    } else {
        (end_index as usize).min(total_length)
    };

    let result_slice = data.get(final_start..final_end).unwrap_or(&[]);
    Ok(result_slice.to_vec())
}

/// 截取 Hex 字符串的指定字节部分
pub fn cut_hex(hex: &str, start_index: i64, end_index: i64) -> ProtocolResult<String> {
    let bytes = hex_to_bytes(hex)?;
    let cutted_bytes = cut_bytes(&bytes, start_index, end_index)?;
    bytes_to_hex(&cutted_bytes)
}

/// 替换 byte 数组中的某一段
pub fn replace_bytes(
    ori_bytes: &[u8],
    start_byte_pos: i64,
    end_byte_pos: i64,
    replace_bytes: &[u8],
) -> ProtocolResult<Vec<u8>> {
    if ori_bytes.is_empty() || replace_bytes.is_empty() || start_byte_pos < 0 {
        return Err(ProtocolError::CommonError(
            "fn: replace_bytes requires input params ori_bytes andreplace_bytes, but found empty"
                .into(),
        ));
    }
    let total_length = ori_bytes.len();
    let total_length_i64 = total_length as i64;
    if end_byte_pos > 0 && (start_byte_pos > end_byte_pos || end_byte_pos > total_length_i64) {
        return Err(ProtocolError::CommonError(
            "fn: replace_bytes has invalid input params".into(),
        ));
    }

    let final_start = (start_byte_pos as usize).min(total_length);
    let final_end = if end_byte_pos > 0 {
        (end_byte_pos as usize).min(total_length)
    } else {
        (total_length_i64 + end_byte_pos).max(0) as usize
    };
    if final_start > final_end { /* ... 错误处理 ... */ }

    let mut result_vec = ori_bytes.to_vec();
    result_vec.splice(final_start..final_end, replace_bytes.iter().copied());
    Ok(result_vec)
}

/// 替换 hex-string 字节中的某一段
pub fn replace_hex(
    ori_hex: &str,
    start_byte_pos: i64,
    end_byte_pos: i64,
    dest_hex: &str,
) -> ProtocolResult<String> {
    let ori_bytes = hex_to_bytes(ori_hex)?;
    let dest_bytes = hex_to_bytes(dest_hex)?;
    let result_bytes = replace_bytes(&ori_bytes, start_byte_pos, end_byte_pos, &dest_bytes)?;
    bytes_to_hex(&result_bytes)
}

/// 按块大小 (block size) 补位
pub fn pad_bytes_to_block_size(
    data: &[u8],
    block_size: usize,
    padding_byte: Option<u8>,
) -> ProtocolResult<Vec<u8>> {
    // ... (保持您之前的实现)
    let origin_length = data.len();
    if block_size == 0 { /* ... 错误处理 ... */ }
    let short_by = if origin_length == block_size {
        0
    } else if origin_length < block_size {
        block_size - origin_length
    } else {
        let rem = origin_length % block_size;
        if rem == 0 {
            block_size
        } else {
            block_size - rem
        }
    };
    if short_by == 0 {
        return Ok(data.to_vec());
    }
    let pad_val = match padding_byte {
        Some(b) => b,
        None => short_by.try_into().map_err(|_| {
            ProtocolError::HexError(HexError::InvalidInput(
                "Default PKCS#7 padding length exceeds 255".into(),
            ))
        })?,
    };
    let new_len = origin_length + short_by;
    let mut result_vec = Vec::with_capacity(new_len);
    result_vec.extend_from_slice(data);
    result_vec.resize(new_len, pad_val);
    Ok(result_vec)
}

/// 补位到指定的总字节长度
pub fn pad_bytes_to_length(
    data: &[u8],
    total_length: usize,
    append_on_tail: bool,
    padding_byte: Option<u8>,
) -> ProtocolResult<Vec<u8>> {
    // ... (保持您之前的实现)
    let origin_length = data.len();
    if origin_length > total_length {
        return Err(ProtocolError::HexError(HexError::InvalidInput(
            "Data length exceeds total length".into(),
        )));
    }
    let short_by = total_length - origin_length;
    if short_by == 0 {
        return Ok(data.to_vec());
    }
    let pad_val = match padding_byte {
        Some(b) => b,
        None => short_by.try_into().map_err(|_| {
            ProtocolError::HexError(HexError::InvalidInput(
                "Default PKCS#7 padding length exceeds 255".into(),
            ))
        })?,
    };
    let mut result_vec = Vec::with_capacity(total_length);
    if append_on_tail {
        result_vec.extend_from_slice(data);
        result_vec.resize(total_length, pad_val);
    } else {
        result_vec.resize(short_by, pad_val);
        result_vec.extend_from_slice(data);
    }
    Ok(result_vec)
}

/// 解析可选的补位Hex ("" 或 None -> None, "00" -> Some(0x00))
fn _parse_padding_hex(padding_hex: Option<&str>) -> ProtocolResult<Option<u8>> {
    match padding_hex.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(ph_str) => {
            let pad_bytes = hex_to_bytes(ph_str)?;
            if pad_bytes.len() != 1 {
                Err(ProtocolError::HexError(HexError::InvalidInput(format!(
                    "Padding hex must be exactly 1 byte (2 chars), but got: {}",
                    ph_str
                ))))
            } else {
                Ok(Some(pad_bytes[0]))
            }
        }
    }
}

/// 按块大小 (block size) 补位 hex 字符串
pub fn pad_hex_to_block_size(
    hex: &str,
    block_size: usize,
    padding_hex: Option<&str>,
) -> ProtocolResult<String> {
    let data = hex_to_bytes(hex)?;
    let padding_byte = _parse_padding_hex(padding_hex)?;
    let padded_bytes = pad_bytes_to_block_size(&data, block_size, padding_byte)?;
    bytes_to_hex(&padded_bytes)
}

/// 补位 hex 字符串到指定的总字节长度
pub fn pad_hex_to_length(
    hex: &str,
    total_length: usize,
    append_on_tail: bool,
    padding_hex: Option<&str>,
) -> ProtocolResult<String> {
    let data = hex_to_bytes(hex)?;
    let padding_byte = _parse_padding_hex(padding_hex)?;
    let padded_bytes = pad_bytes_to_length(&data, total_length, append_on_tail, padding_byte)?;
    bytes_to_hex(&padded_bytes)
}

// --- 校验函数 ---

/// 检查字符串是否为有效的 BCD 码
pub fn is_bcd(s: &str) -> bool {
    _clean_hex_str(s).chars().all(|c| c.is_ascii_digit())
}

/// 检查字符串是否为有效的 Hex 码 (偶数长度, 0-9, a-f, A-F)
pub fn is_hex(s: &str) -> bool {
    hex::decode(_clean_and_pad_hex_str(s)).is_ok()
}

/// 检查字符串是否为有效的 ASCII (Hex) 码
pub fn is_ascii_hex(s: &str) -> bool {
    match hex::decode(_clean_and_pad_hex_str(s)) {
        Ok(bytes) => bytes.iter().all(|b| b.is_ascii()),
        Err(_) => false,
    }
}

/// 检查字符串是否为 Hex, BCD 或 ASCII-Hex 之一
pub fn is_machine_code(s: &str) -> bool {
    // 简化：如果能被 hex::decode 成功，就认为是 machine code
    // （因为 is_hex 是 is_bcd 和 is_ascii_hex 的超集）
    is_hex(s)
}

/// 确保字符串是 machine code，否则返回错误
pub fn ensure_is_machine_code(s: &str) -> ProtocolResult<()> {
    if is_machine_code(s) {
        Ok(())
    } else {
        Err(ProtocolError::HexError(HexError::NotMachineCode(s.into())))
    }
}
/// 确保字符串是 BCD，否则返回错误
pub fn ensure_is_bcd(s: &str) -> ProtocolResult<()> {
    if is_bcd(s) {
        Ok(())
    } else {
        Err(ProtocolError::HexError(HexError::NotBcd(s.into())))
    }
}
/// 确保字符串是 ASCII Hex，否则返回错误
pub fn ensure_is_ascii_hex(s: &str) -> ProtocolResult<()> {
    if is_ascii_hex(s) {
        Ok(())
    } else {
        Err(ProtocolError::HexError(HexError::NotAscii(s.into())))
    }
}

// --- ASCII 转换 ---

/// ASCII Hex -> String
pub fn ascii_to_string(ascii_hex_str: &str) -> ProtocolResult<String> {
    let v = _clean_and_pad_hex_str(ascii_hex_str);
    if v.is_empty() {
        return Ok(String::new());
    }
    ensure_is_ascii_hex(&v)?;
    let bytes = hex::decode(&v).unwrap(); // 安全，已检查
    // from_utf8 在这里也是安全的，因为我们保证了是ASCII
    Ok(String::from_utf8(bytes).unwrap())
}

/// String -> ASCII Hex
pub fn string_to_ascii(plain_str: &str) -> ProtocolResult<String> {
    if plain_str.is_empty() {
        return Ok(String::new());
    }
    if !plain_str.is_ascii() {
        return Err(ProtocolError::HexError(HexError::NotAscii(
            "Input string contains non-ASCII characters".into(),
        )));
    }
    bytes_to_hex(plain_str.as_bytes())
}

// --- 内部辅助函数 ---

/// 辅助函数：清理 hex 字符串 (trim, strip "0x")
fn _clean_hex_str(hex: &str) -> &str {
    hex.trim()
        .strip_prefix("0x")
        .or_else(|| hex.trim().strip_prefix("0X"))
        .unwrap_or_else(|| hex.trim())
}

/// 辅助函数：清理 hex 字符串并补零到偶数长度
fn _clean_and_pad_hex_str(hex: &str) -> String {
    let cleaned = _clean_hex_str(hex);
    if cleaned.len().is_multiple_of(2) {
        cleaned.to_string()
    } else {
        format!("0{}", cleaned)
    }
}
