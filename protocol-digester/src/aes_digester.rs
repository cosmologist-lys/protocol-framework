//! AES加密解密模块
//!
//! 提供多种AES加密模式的实现，包括ECB、CBC、CFB、CTR、OFB、CTS等
//!
//! # 警告抑制说明
//! 由于使用了aes crate内部的GenericArray，会产生deprecation警告
//! 这是因为generic-array crate版本兼容性问题，暂时抑制警告

#![allow(deprecated)]

use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use protocol_base::{
    ProtocolResult,
    error::{ProtocolError, hex_error::HexError},
};
use rand::RngCore;

/// AES操作模式枚举
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AesMode {
    /// 无加密模式
    NONE,
    /// 密码分组链接模式(Cipher Block Chaining)
    CBC,
    /// 密码反馈模式(Cipher Feedback)
    CFB,
    /// 计数器模式(Counter)
    CTR,
    /// 密文窃取模式(Cipher Text Stealing)
    CTS,
    /// 电子密码本模式(Electronic Code Book)
    ECB,
    /// 输出反馈模式(Output Feedback)
    OFB,
}

/// AES加密器结构体
///
/// 支持AES-128加密，提供多种加密模式
pub struct AesCipher {
    cipher: Aes128,
    mode: AesMode,
}

impl AesCipher {
    /// 创建新的AES加密器
    ///
    /// # 参数
    /// * `key` - 16字节的AES-128密钥
    /// * `mode` - 加密模式
    ///
    /// # 返回
    /// 成功时返回AesCipher实例，失败时返回错误信息
    pub fn new(key: &[u8], mode: AesMode) -> ProtocolResult<Self> {
        if key.len() != 16 {
            return Err(ProtocolError::InvalidKeyLength { actual: key.len() });
        }

        let key_array = GenericArray::from_slice(key);
        let cipher = Aes128::new(key_array);

        Ok(AesCipher { cipher, mode })
    }

    /// 获取当前的加密模式
    pub fn mode(&self) -> AesMode {
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
            AesMode::ECB => self.encrypt_ecb(data),
            AesMode::CBC => self.encrypt_cbc(data, iv),
            AesMode::CFB => self.encrypt_cfb(data, iv),
            AesMode::CTR => self.encrypt_ctr(data, iv),
            AesMode::OFB => self.encrypt_ofb(data, iv),
            AesMode::CTS => self.encrypt_cts(data, iv),
            AesMode::NONE => self.encrypt_none(data),
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
            AesMode::ECB => self.decrypt_ecb(data),
            AesMode::CBC => self.decrypt_cbc(data, iv),
            AesMode::CFB => self.decrypt_cfb(data, iv),
            AesMode::CTR => self.decrypt_ctr(data, iv),
            AesMode::OFB => self.decrypt_ofb(data, iv),
            AesMode::CTS => self.decrypt_cts(data, iv),
            AesMode::NONE => self.decrypt_none(data),
        }
    }

    // ECB模式加密
    fn encrypt_ecb(&self, data: &[u8]) -> ProtocolResult<Vec<u8>> {
        let padded_data = self.pkcs7_pad(data);
        let mut result = Vec::with_capacity(padded_data.len());

        for chunk in padded_data.chunks(16) {
            let mut block = GenericArray::clone_from_slice(chunk);
            self.cipher.encrypt_block(&mut block);
            result.extend_from_slice(&block);
        }

        Ok(result)
    }

    // ECB模式解密
    fn decrypt_ecb(&self, data: &[u8]) -> ProtocolResult<Vec<u8>> {
        if !data.len().is_multiple_of(16) {
            return Err(ProtocolError::ValidationFailed(
                "Data length must be multiple of 16 bytes".into(),
            ));
        }

        let mut result = Vec::with_capacity(data.len());

        for chunk in data.chunks(16) {
            let mut block = GenericArray::clone_from_slice(chunk);
            self.cipher.decrypt_block(&mut block);
            result.extend_from_slice(&block);
        }

        self.pkcs7_unpad(&result)
    }

    // CBC模式加密
    fn encrypt_cbc(&self, data: &[u8], iv: &[u8]) -> ProtocolResult<Vec<u8>> {
        if iv.len() != 16 {
            return Err(ProtocolError::ValidationFailed(
                "IV must be 16 bytes".into(),
            ));
        }

        let padded_data = self.pkcs7_pad(data);
        let mut result = Vec::with_capacity(padded_data.len());
        let mut prev_block = GenericArray::clone_from_slice(iv);

        for chunk in padded_data.chunks(16) {
            let mut block = GenericArray::clone_from_slice(chunk);

            // XOR with previous ciphertext block (or IV for first block)
            for i in 0..16 {
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
        if iv.len() != 16 {
            return Err(ProtocolError::ValidationFailed(
                "IV must be 16 bytes".into(),
            ));
        }
        if !data.len().is_multiple_of(16) {
            return Err(ProtocolError::ValidationFailed(
                "Data length must be multiple of 16 bytes".into(),
            ));
        }

        let mut result = Vec::with_capacity(data.len());
        let mut prev_block = GenericArray::clone_from_slice(iv);

        for chunk in data.chunks(16) {
            let mut block = GenericArray::clone_from_slice(chunk);
            let current_block = block;

            self.cipher.decrypt_block(&mut block);

            // XOR with previous ciphertext block (or IV for first block)
            for i in 0..16 {
                block[i] ^= prev_block[i];
            }

            result.extend_from_slice(&block);
            prev_block = current_block;
        }

        self.pkcs7_unpad(&result)
    }

    // CFB模式加密
    fn encrypt_cfb(&self, data: &[u8], iv: &[u8]) -> ProtocolResult<Vec<u8>> {
        if iv.len() != 16 {
            return Err(ProtocolError::ValidationFailed(
                "IV must be 16 bytes".into(),
            ));
        }

        let mut result = Vec::with_capacity(data.len());
        let mut feedback = GenericArray::clone_from_slice(iv);

        for chunk in data.chunks(16) {
            let mut block = feedback;
            self.cipher.encrypt_block(&mut block);

            let mut output = Vec::with_capacity(chunk.len());
            for (i, &byte) in chunk.iter().enumerate() {
                output.push(byte ^ block[i]);
            }

            // For CFB, the ciphertext becomes the next feedback
            feedback = GenericArray::clone_from_slice(&output);
            if output.len() < 16 {
                // Pad if necessary for last block
                output.resize(16, 0);
                feedback = GenericArray::clone_from_slice(&output);
            }

            result.extend_from_slice(&output[..chunk.len()]);
        }

        Ok(result)
    }

    // CFB模式解密
    fn decrypt_cfb(&self, data: &[u8], iv: &[u8]) -> ProtocolResult<Vec<u8>> {
        if iv.len() != 16 {
            return Err(ProtocolError::ValidationFailed(
                "IV must be 16 bytes".into(),
            ));
        }

        let mut result = Vec::with_capacity(data.len());
        let mut feedback = GenericArray::clone_from_slice(iv);

        for chunk in data.chunks(16) {
            let mut block = feedback;
            self.cipher.encrypt_block(&mut block);

            let mut output = Vec::with_capacity(chunk.len());
            for (i, &byte) in chunk.iter().enumerate() {
                output.push(byte ^ block[i]);
            }

            // For CFB decryption, the ciphertext becomes the next feedback
            feedback = GenericArray::clone_from_slice(chunk);
            if chunk.len() < 16 {
                let mut padded_chunk = chunk.to_vec();
                padded_chunk.resize(16, 0);
                feedback = GenericArray::clone_from_slice(&padded_chunk);
            }

            result.extend_from_slice(&output);
        }

        Ok(result)
    }

    // CTR模式加密
    fn encrypt_ctr(&self, data: &[u8], iv: &[u8]) -> ProtocolResult<Vec<u8>> {
        if iv.len() != 16 {
            return Err(ProtocolError::ValidationFailed(
                "IV must be 16 bytes".into(),
            ));
        }

        let mut result = Vec::with_capacity(data.len());
        let mut counter = u128::from_be_bytes(iv.try_into().unwrap());

        for chunk in data.chunks(16) {
            let nonce = counter.to_be_bytes();
            let mut block = GenericArray::clone_from_slice(&nonce);
            self.cipher.encrypt_block(&mut block);

            for (i, &byte) in chunk.iter().enumerate() {
                result.push(byte ^ block[i]);
            }

            counter = counter.wrapping_add(1);
        }

        Ok(result)
    }

    // CTR模式解密
    fn decrypt_ctr(&self, data: &[u8], iv: &[u8]) -> ProtocolResult<Vec<u8>> {
        // CTR模式加密解密相同
        self.encrypt_ctr(data, iv)
    }

    // OFB模式加密
    fn encrypt_ofb(&self, data: &[u8], iv: &[u8]) -> ProtocolResult<Vec<u8>> {
        if iv.len() != 16 {
            return Err(ProtocolError::ValidationFailed(
                "IV must be 16 bytes".into(),
            ));
        }

        let mut result = Vec::with_capacity(data.len());
        let mut feedback = GenericArray::clone_from_slice(iv);

        for chunk in data.chunks(16) {
            let mut block = feedback;
            self.cipher.encrypt_block(&mut block);
            feedback = block;

            for (i, &byte) in chunk.iter().enumerate() {
                result.push(byte ^ block[i]);
            }
        }

        Ok(result)
    }

    // OFB模式解密
    fn decrypt_ofb(&self, data: &[u8], iv: &[u8]) -> ProtocolResult<Vec<u8>> {
        // OFB模式加密解密相同
        self.encrypt_ofb(data, iv)
    }

    // CTS模式加密
    fn encrypt_cts(&self, data: &[u8], iv: &[u8]) -> ProtocolResult<Vec<u8>> {
        if iv.len() != 16 {
            return Err(ProtocolError::ValidationFailed(
                "IV must be 16 bytes".into(),
            ));
        }

        let block_size = 16;
        let data_len = data.len();

        if data_len < block_size {
            return Err(ProtocolError::InputTooShort {
                needed: block_size,
                available: data_len,
            });
        }

        let full_blocks = data_len / block_size;
        let remainder = data_len % block_size;

        if remainder == 0 {
            // No stealing needed, use standard CBC
            return self.encrypt_cbc(data, iv);
        }

        let mut result = Vec::with_capacity(data_len);

        // Encrypt all but the last two blocks using standard CBC
        if full_blocks > 1 {
            let main_data = &data[..(full_blocks - 1) * block_size];
            let main_encrypted = self.encrypt_cbc(main_data, iv)?;
            result.extend_from_slice(&main_encrypted);
        }

        // Handle the last two blocks with ciphertext stealing
        let second_last_block = &data[(full_blocks - 1) * block_size..full_blocks * block_size];
        let last_block = &data[full_blocks * block_size..];

        // Pad the last block
        let mut padded_last = last_block.to_vec();
        padded_last.resize(block_size, 0);

        // Encrypt the padded last block
        let mut temp_block = GenericArray::clone_from_slice(&padded_last);
        self.cipher.encrypt_block(&mut temp_block);

        // The second last ciphertext block is the encrypted last block
        result.extend_from_slice(&temp_block[..remainder]);

        // The last ciphertext block is the encrypted second last block
        let mut second_last_encrypted = GenericArray::clone_from_slice(second_last_block);
        self.cipher.encrypt_block(&mut second_last_encrypted);
        result.extend_from_slice(&second_last_encrypted);

        Ok(result)
    }

    // CTS模式解密
    fn decrypt_cts(&self, data: &[u8], iv: &[u8]) -> ProtocolResult<Vec<u8>> {
        if iv.len() != 16 {
            return Err(ProtocolError::ValidationFailed(
                "IV must be 16 bytes".into(),
            ));
        }

        let block_size = 16;
        let data_len = data.len();

        if data_len < block_size {
            return Err(ProtocolError::InputTooShort {
                needed: block_size,
                available: data_len,
            });
        }

        let full_blocks = data_len / block_size;
        let remainder = data_len % block_size;

        if remainder == 0 {
            // No stealing needed, use standard CBC
            return self.decrypt_cbc(data, iv);
        }

        let mut result = Vec::with_capacity(data_len);

        // Decrypt all but the last two blocks using standard CBC
        if full_blocks > 1 {
            let main_data = &data[..(full_blocks - 1) * block_size];
            let main_decrypted = self.decrypt_cbc(main_data, iv)?;
            result.extend_from_slice(&main_decrypted);
        }

        // Handle the last two blocks with ciphertext stealing
        let stolen_part =
            &data[(full_blocks - 1) * block_size..(full_blocks - 1) * block_size + remainder];
        let last_block = &data[(full_blocks - 1) * block_size + remainder..];

        // Decrypt the last block to get the second last plaintext
        let mut temp_block = GenericArray::clone_from_slice(last_block);
        self.cipher.decrypt_block(&mut temp_block);
        result.extend_from_slice(&temp_block);

        // Reconstruct and decrypt the stolen block
        let mut stolen_block = stolen_part.to_vec();
        stolen_block.extend_from_slice(&temp_block[remainder..]);

        let mut stolen_decrypted = GenericArray::clone_from_slice(&stolen_block);
        self.cipher.decrypt_block(&mut stolen_decrypted);
        result.extend_from_slice(&stolen_decrypted[..remainder]);

        Ok(result)
    }

    // NONE模式 - 直接返回数据（无加密）
    fn encrypt_none(&self, data: &[u8]) -> ProtocolResult<Vec<u8>> {
        Ok(data.to_vec())
    }

    // NONE模式解密
    fn decrypt_none(&self, data: &[u8]) -> ProtocolResult<Vec<u8>> {
        Ok(data.to_vec())
    }

    // PKCS7填充
    fn pkcs7_pad(&self, data: &[u8]) -> Vec<u8> {
        let block_size = 16;
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

        if padding_len == 0 || padding_len > 16 {
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

/// 生成随机的16字节初始化向量(IV)
///
/// # 返回
/// 16字节的随机IV数组
pub fn generate_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
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

/// 便捷函数：创建ECB模式的AES加密器
pub fn new_ecb_cipher(key: &[u8]) -> ProtocolResult<AesCipher> {
    AesCipher::new(key, AesMode::ECB)
}

/// 便捷函数：创建CBC模式的AES加密器
pub fn new_cbc_cipher(key: &[u8]) -> ProtocolResult<AesCipher> {
    AesCipher::new(key, AesMode::CBC)
}

/// 便捷函数：创建CTR模式的AES加密器
pub fn new_ctr_cipher(key: &[u8]) -> ProtocolResult<AesCipher> {
    AesCipher::new(key, AesMode::CTR)
}
