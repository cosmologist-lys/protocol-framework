//! DES加密解密模块
//!
//! 提供DES加密模式的实现，包括ECB、CBC等
//!
//! # 示例
//!
//! ## ECB模式加密解密
//!
//! ```
//! use protocol_digester::des_digester::{DesCipher, DesMode};
//!
//! let key = b"12345678"; // 8字节密钥
//! let plaintext = b"Hello, DES!";
//!
//! // 创建ECB模式的加密器
//! let cipher = DesCipher::new(key, DesMode::ECB).unwrap();
//!
//! // 加密
//! let encrypted = cipher.encrypt(plaintext, &[]).unwrap();
//!
//! // 解密
//! let decrypted = cipher.decrypt(&encrypted, &[]).unwrap();
//! assert_eq!(plaintext, &decrypted[..]);
//! ```
//!
//! ## CBC模式加密解密
//!
//! ```
//! use protocol_digester::des_digester::{DesCipher, DesMode, generate_iv};
//!
//! let key = b"12345678"; // 8字节密钥
//! let iv = generate_iv(); // 生成8字节随机IV
//! let plaintext = b"Hello, DES CBC mode!";
//!
//! // 创建CBC模式的加密器
//! let cipher = DesCipher::new(key, DesMode::CBC).unwrap();
//!
//! // 加密
//! let encrypted = cipher.encrypt(plaintext, &iv).unwrap();
//!
//! // 解密
//! let decrypted = cipher.decrypt(&encrypted, &iv).unwrap();
//! assert_eq!(plaintext, &decrypted[..]);
//! ```
//!
//! ## 使用便捷函数
//!
//! ```
//! use protocol_digester::des_digester::{new_ecb_cipher, new_cbc_cipher, generate_iv, to_hex};
//!
//! let key = b"12345678";
//! let plaintext = b"Secret message";
//!
//! // 使用ECB模式
//! let ecb_cipher = new_ecb_cipher(key).unwrap();
//! let encrypted = ecb_cipher.encrypt(plaintext, &[]).unwrap();
//! println!("加密后(十六进制): {}", to_hex(&encrypted));
//!
//! // 使用CBC模式
//! let cbc_cipher = new_cbc_cipher(key).unwrap();
//! let iv = generate_iv();
//! let encrypted = cbc_cipher.encrypt(plaintext, &iv).unwrap();
//! let decrypted = cbc_cipher.decrypt(&encrypted, &iv).unwrap();
//! assert_eq!(plaintext, &decrypted[..]);
//! ```
//!
//! # 警告抑制说明
//! 由于使用了des crate内部的GenericArray，会产生deprecation警告
//! 这是因为generic-array crate版本兼容性问题，暂时抑制警告

#![allow(deprecated)]

use des::Des;
use des::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use protocol_base::{
    ProtocolResult,
    error::{ProtocolError, hex_error::HexError},
};
use rand::RngCore;

/// DES操作模式枚举
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DesMode {
    /// 无加密模式
    NONE,
    /// 密码分组链接模式(Cipher Block Chaining)
    CBC,
    /// 电子密码本模式(Electronic Code Book)
    ECB,
}

/// DES加密器结构体
///
/// 支持DES加密，提供多种加密模式
pub struct DesCipher {
    cipher: Des,
    mode: DesMode,
}

impl DesCipher {
    /// 创建新的DES加密器
    ///
    /// # 参数
    /// * `key` - 8字节的DES密钥
    /// * `mode` - 加密模式
    ///
    /// # 返回
    /// 成功时返回DesCipher实例，失败时返回错误信息
    pub fn new(key: &[u8], mode: DesMode) -> ProtocolResult<Self> {
        if key.len() != 8 {
            return Err(ProtocolError::InvalidKeyLength { actual: key.len() });
        }

        let key_array = GenericArray::from_slice(key);
        let cipher = Des::new(key_array);

        Ok(DesCipher { cipher, mode })
    }

    /// 获取当前的加密模式
    pub fn mode(&self) -> DesMode {
        self.mode
    }

    /// 加密数据
    ///
    /// # 参数
    /// * `data` - 要加密的数据
    /// * `iv` - 初始化向量(某些模式需要，ECB和NONE模式会忽略)
    ///
    /// # 返回
    /// 成功时返回加密后的数据，失败时返回错误信息
    pub fn encrypt(&self, data: &[u8], iv: &[u8]) -> ProtocolResult<Vec<u8>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        match self.mode {
            DesMode::ECB => self.encrypt_ecb(data),
            DesMode::CBC => self.encrypt_cbc(data, iv),
            DesMode::NONE => self.encrypt_none(data),
        }
    }

    /// 解密数据
    ///
    /// # 参数
    /// * `data` - 要解密的数据
    /// * `iv` - 初始化向量(某些模式需要，ECB和NONE模式会忽略)
    ///
    /// # 返回
    /// 成功时返回解密后的数据，失败时返回错误信息
    pub fn decrypt(&self, data: &[u8], iv: &[u8]) -> ProtocolResult<Vec<u8>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        match self.mode {
            DesMode::ECB => self.decrypt_ecb(data),
            DesMode::CBC => self.decrypt_cbc(data, iv),
            DesMode::NONE => self.decrypt_none(data),
        }
    }

    // ECB模式加密
    fn encrypt_ecb(&self, data: &[u8]) -> ProtocolResult<Vec<u8>> {
        let padded_data = self.pkcs7_pad(data);
        let mut result = Vec::with_capacity(padded_data.len());

        for chunk in padded_data.chunks(8) {
            let mut block = GenericArray::clone_from_slice(chunk);
            self.cipher.encrypt_block(&mut block);
            result.extend_from_slice(&block);
        }

        Ok(result)
    }

    // ECB模式解密
    fn decrypt_ecb(&self, data: &[u8]) -> ProtocolResult<Vec<u8>> {
        if !data.len().is_multiple_of(8) {
            return Err(ProtocolError::ValidationFailed(
                "Data length must be multiple of 8 bytes".into(),
            ));
        }

        let mut result = Vec::with_capacity(data.len());

        for chunk in data.chunks(8) {
            let mut block = GenericArray::clone_from_slice(chunk);
            self.cipher.decrypt_block(&mut block);
            result.extend_from_slice(&block);
        }

        self.pkcs7_unpad(&result)
    }

    // CBC模式加密
    fn encrypt_cbc(&self, data: &[u8], iv: &[u8]) -> ProtocolResult<Vec<u8>> {
        if iv.len() != 8 {
            return Err(ProtocolError::ValidationFailed(
                "IV must be 8 bytes for DES".into(),
            ));
        }

        let padded_data = self.pkcs7_pad(data);
        let mut result = Vec::with_capacity(padded_data.len());
        let mut prev_block = GenericArray::clone_from_slice(iv);

        for chunk in padded_data.chunks(8) {
            let mut block = GenericArray::clone_from_slice(chunk);

            // XOR with previous ciphertext block (or IV for first block)
            for i in 0..8 {
                block[i] ^= prev_block[i];
            }

            self.cipher.encrypt_block(&mut block);
            result.extend_from_slice(&block);
            prev_block = block;
        }

        Ok(result)
    }

    // CBC模式解密
    fn decrypt_cbc(&self, data: &[u8], iv: &[u8]) -> ProtocolResult<Vec<u8>> {
        if iv.len() != 8 {
            return Err(ProtocolError::ValidationFailed(
                "IV must be 8 bytes for DES".into(),
            ));
        }

        if !data.len().is_multiple_of(8) {
            return Err(ProtocolError::ValidationFailed(
                "Data length must be multiple of 8 bytes".into(),
            ));
        }

        let mut result = Vec::with_capacity(data.len());
        let mut prev_block = GenericArray::clone_from_slice(iv);

        for chunk in data.chunks(8) {
            let cipher_block = GenericArray::clone_from_slice(chunk);
            let mut block = cipher_block;

            self.cipher.decrypt_block(&mut block);

            // XOR with previous ciphertext block (or IV for first block)
            for i in 0..8 {
                block[i] ^= prev_block[i];
            }

            result.extend_from_slice(&block);
            prev_block = cipher_block;
        }

        self.pkcs7_unpad(&result)
    }

    // NONE模式加密（无加密）
    fn encrypt_none(&self, data: &[u8]) -> ProtocolResult<Vec<u8>> {
        Ok(data.to_vec())
    }

    // NONE模式解密（无解密）
    fn decrypt_none(&self, data: &[u8]) -> ProtocolResult<Vec<u8>> {
        Ok(data.to_vec())
    }

    // PKCS7填充
    fn pkcs7_pad(&self, data: &[u8]) -> Vec<u8> {
        let block_size = 8;
        let padding_len = block_size - (data.len() % block_size);
        let padding_byte = padding_len as u8;

        let mut padded = data.to_vec();
        padded.resize(data.len() + padding_len, padding_byte);
        padded
    }

    // PKCS7去除填充
    fn pkcs7_unpad(&self, data: &[u8]) -> ProtocolResult<Vec<u8>> {
        if data.is_empty() {
            return Ok(vec![]);
        }

        let padding_byte = data[data.len() - 1];
        let padding_len = padding_byte as usize;

        if padding_len == 0 || padding_len > 8 {
            return Err(ProtocolError::CryptoError("Invalid padding".into()));
        }

        // Verify padding bytes
        for &byte in &data[data.len() - padding_len..] {
            if byte != padding_byte {
                return Err(ProtocolError::CryptoError("Invalid padding".into()));
            }
        }

        Ok(data[..data.len() - padding_len].to_vec())
    }
}

/// 生成随机的8字节初始化向量(IV)
///
/// # 返回
/// 8字节的随机IV数组
pub fn generate_iv() -> [u8; 8] {
    let mut iv = [0u8; 8];
    rand::rng().fill_bytes(&mut iv);
    iv
}

/// 将字节数据转换为十六进制字符串
///
/// # 参数
/// * `data` - 要转换的字节数据
///
/// # 返回
/// 十六进制字符串表示
pub fn to_hex(data: &[u8]) -> String {
    hex::encode(data)
}

/// 从十六进制字符串解析字节数据
///
/// # 参数
/// * `hex_str` - 十六进制字符串
///
/// # 返回
/// 成功时返回字节向量，失败时返回解析错误
pub fn from_hex(hex_str: &str) -> ProtocolResult<Vec<u8>> {
    hex::decode(hex_str).map_err(|e| ProtocolError::HexError(HexError::InvalidInput(e.to_string())))
}

/// 便捷函数：创建ECB模式的DES加密器
pub fn new_ecb_cipher(key: &[u8]) -> ProtocolResult<DesCipher> {
    DesCipher::new(key, DesMode::ECB)
}

/// 便捷函数：创建CBC模式的DES加密器
pub fn new_cbc_cipher(key: &[u8]) -> ProtocolResult<DesCipher> {
    DesCipher::new(key, DesMode::CBC)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_des_ecb_encrypt_decrypt() {
        let key = b"12345678"; // 8 bytes key
        let plaintext = b"Hello, DES!";

        let cipher = DesCipher::new(key, DesMode::ECB).unwrap();
        let encrypted = cipher.encrypt(plaintext, &[]).unwrap();
        let decrypted = cipher.decrypt(&encrypted, &[]).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_des_cbc_encrypt_decrypt() {
        let key = b"12345678"; // 8 bytes key
        let iv = generate_iv();
        let plaintext = b"Hello, DES CBC mode!";

        let cipher = DesCipher::new(key, DesMode::CBC).unwrap();
        let encrypted = cipher.encrypt(plaintext, &iv).unwrap();
        let decrypted = cipher.decrypt(&encrypted, &iv).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_des_invalid_key_length() {
        let key = b"1234567"; // 7 bytes - invalid
        let result = DesCipher::new(key, DesMode::ECB);
        assert!(result.is_err());
    }

    #[test]
    fn test_des_empty_data() {
        let key = b"12345678";
        let cipher = DesCipher::new(key, DesMode::ECB).unwrap();

        let encrypted = cipher.encrypt(&[], &[]).unwrap();
        assert!(encrypted.is_empty());

        let decrypted = cipher.decrypt(&[], &[]).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_pkcs7_padding() {
        let key = b"12345678";
        let cipher = DesCipher::new(key, DesMode::ECB).unwrap();

        // Test data that needs padding
        let data = b"Hello"; // 5 bytes, needs 3 bytes padding
        let padded = cipher.pkcs7_pad(data);
        assert_eq!(padded.len(), 8); // Should be padded to 8 bytes
        assert_eq!(padded[5], 3); // Padding byte value should be 3
        assert_eq!(padded[6], 3);
        assert_eq!(padded[7], 3);
    }

    #[test]
    fn test_hex_conversion() {
        let data = b"Hello";
        let hex_str = to_hex(data);
        let decoded = from_hex(&hex_str).unwrap();
        assert_eq!(data, &decoded[..]);
    }

    #[test]
    fn test_convenience_functions() {
        let key = b"12345678";

        let ecb_cipher = new_ecb_cipher(key).unwrap();
        assert_eq!(ecb_cipher.mode(), DesMode::ECB);

        let cbc_cipher = new_cbc_cipher(key).unwrap();
        assert_eq!(cbc_cipher.mode(), DesMode::CBC);
    }
}
