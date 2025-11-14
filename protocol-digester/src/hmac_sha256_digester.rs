//! HMAC-SHA256 消息认证码模块
//!
//! 提供基于 SHA256 的 HMAC (Hash-based Message Authentication Code) 实现
//! HMAC 是一种使用密钥的消息认证码算法，用于验证消息的完整性和真实性
//!
//! # 示例
//!
//! ## 基本用法
//!
//! ```
//! use protocol_digester::hmac_sha256_digester::HmacSha256Digester;
//!
//! let key = b"secret_key";
//! let message = b"Hello, HMAC!";
//!
//! // 生成 HMAC
//! let hmac = HmacSha256Digester::digest(message, key).unwrap();
//! println!("HMAC: {}", hmac);
//!
//! // 验证 HMAC
//! let is_valid = HmacSha256Digester::verify(message, key, &hmac).unwrap();
//! assert!(is_valid);
//! ```
//!
//! ## 字符串操作
//!
//! ```
//! use protocol_digester::hmac_sha256_digester::HmacSha256Digester;
//!
//! let key = "my_secret_key";
//! let message = "Important message";
//!
//! // 生成 HMAC
//! let hmac = HmacSha256Digester::digest_str(message, key).unwrap();
//!
//! // 验证 HMAC
//! let is_valid = HmacSha256Digester::verify_str(message, key, &hmac).unwrap();
//! assert!(is_valid);
//! ```
//!
//! ## 原始字节输出
//!
//! ```
//! use protocol_digester::hmac_sha256_digester::HmacSha256Digester;
//!
//! let key = b"secret";
//! let message = b"data";
//!
//! // 获取原始字节格式的 HMAC
//! let hmac_bytes = HmacSha256Digester::digest_raw(message, key).unwrap();
//! assert_eq!(hmac_bytes.len(), 32); // SHA256 输出 32 字节
//! ```

use hmac::{Hmac, Mac};
use protocol_base::ProtocolResult;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 消息认证码生成器
pub struct HmacSha256Digester;

impl HmacSha256Digester {
    /// 对数据进行 HMAC-SHA256 计算，返回十六进制字符串
    ///
    /// # 参数
    /// * `data` - 要认证的消息数据
    /// * `key` - HMAC 密钥
    ///
    /// # 返回
    /// 成功时返回十六进制格式的 HMAC 字符串
    pub fn digest(data: &[u8], key: &[u8]) -> ProtocolResult<String> {
        let result = Self::digest_raw(data, key)?;
        Ok(hex::encode(result))
    }

    /// 对字符串进行 HMAC-SHA256 计算，返回十六进制字符串
    ///
    /// # 参数
    /// * `data` - 要认证的消息字符串
    /// * `key` - HMAC 密钥字符串
    ///
    /// # 返回
    /// 成功时返回十六进制格式的 HMAC 字符串
    pub fn digest_str(data: &str, key: &str) -> ProtocolResult<String> {
        Self::digest(data.as_bytes(), key.as_bytes())
    }

    /// 对数据进行 HMAC-SHA256 计算，返回原始字节
    ///
    /// # 参数
    /// * `data` - 要认证的消息数据
    /// * `key` - HMAC 密钥
    ///
    /// # 返回
    /// 成功时返回 32 字节的 HMAC 结果
    pub fn digest_raw(data: &[u8], key: &[u8]) -> ProtocolResult<Vec<u8>> {
        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|e| protocol_base::error::ProtocolError::CryptoError(e.to_string()))?;

        mac.update(data);
        let result = mac.finalize();
        Ok(result.into_bytes().to_vec())
    }

    /// 对字符串进行 HMAC-SHA256 计算，返回原始字节
    ///
    /// # 参数
    /// * `data` - 要认证的消息字符串
    /// * `key` - HMAC 密钥字符串
    ///
    /// # 返回
    /// 成功时返回 32 字节的 HMAC 结果
    pub fn digest_raw_str(data: &str, key: &str) -> ProtocolResult<Vec<u8>> {
        Self::digest_raw(data.as_bytes(), key.as_bytes())
    }

    /// 验证数据的 HMAC-SHA256 是否匹配
    ///
    /// # 参数
    /// * `data` - 要验证的消息数据
    /// * `key` - HMAC 密钥
    /// * `hmac` - 期望的 HMAC 十六进制字符串
    ///
    /// # 返回
    /// 如果 HMAC 匹配返回 true，否则返回 false
    pub fn verify(data: &[u8], key: &[u8], hmac: &str) -> ProtocolResult<bool> {
        let computed = Self::digest(data, key)?;
        Ok(computed.eq_ignore_ascii_case(hmac))
    }

    /// 验证字符串的 HMAC-SHA256 是否匹配
    ///
    /// # 参数
    /// * `data` - 要验证的消息字符串
    /// * `key` - HMAC 密钥字符串
    /// * `hmac` - 期望的 HMAC 十六进制字符串
    ///
    /// # 返回
    /// 如果 HMAC 匹配返回 true，否则返回 false
    pub fn verify_str(data: &str, key: &str, hmac: &str) -> ProtocolResult<bool> {
        Self::verify(data.as_bytes(), key.as_bytes(), hmac)
    }

    /// 验证数据的 HMAC-SHA256 是否匹配（原始字节比较）
    ///
    /// # 参数
    /// * `data` - 要验证的消息数据
    /// * `key` - HMAC 密钥
    /// * `hmac` - 期望的 HMAC 原始字节
    ///
    /// # 返回
    /// 如果 HMAC 匹配返回 true，否则返回 false
    pub fn verify_raw(data: &[u8], key: &[u8], hmac: &[u8]) -> ProtocolResult<bool> {
        let computed = Self::digest_raw(data, key)?;
        Ok(computed == hmac)
    }

    /// 使用恒定时间比较验证 HMAC（防止时序攻击）
    ///
    /// # 参数
    /// * `data` - 要验证的消息数据
    /// * `key` - HMAC 密钥
    /// * `expected_hmac` - 期望的 HMAC 原始字节
    ///
    /// # 返回
    /// 如果 HMAC 匹配返回 true，否则返回 false
    pub fn verify_constant_time(
        data: &[u8],
        key: &[u8],
        expected_hmac: &[u8],
    ) -> ProtocolResult<bool> {
        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|e| protocol_base::error::ProtocolError::CryptoError(e.to_string()))?;

        mac.update(data);

        // 使用恒定时间比较
        match mac.verify_slice(expected_hmac) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Base64 编码的 HMAC-SHA256 计算
    ///
    /// # 参数
    /// * `data` - 要认证的消息数据
    /// * `key` - HMAC 密钥
    ///
    /// # 返回
    /// 成功时返回 Base64 格式的 HMAC 字符串
    pub fn digest_base64(data: &[u8], key: &[u8]) -> ProtocolResult<String> {
        let result = Self::digest_raw(data, key)?;
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            result,
        ))
    }

    /// Base64 编码的字符串 HMAC-SHA256 计算
    ///
    /// # 参数
    /// * `data` - 要认证的消息字符串
    /// * `key` - HMAC 密钥字符串
    ///
    /// # 返回
    /// 成功时返回 Base64 格式的 HMAC 字符串
    pub fn digest_base64_str(data: &str, key: &str) -> ProtocolResult<String> {
        Self::digest_base64(data.as_bytes(), key.as_bytes())
    }

    /// 验证 Base64 编码的 HMAC-SHA256
    ///
    /// # 参数
    /// * `data` - 要验证的消息数据
    /// * `key` - HMAC 密钥
    /// * `hmac_base64` - 期望的 Base64 格式 HMAC
    ///
    /// # 返回
    /// 如果 HMAC 匹配返回 true，否则返回 false
    pub fn verify_base64(data: &[u8], key: &[u8], hmac_base64: &str) -> ProtocolResult<bool> {
        let computed = Self::digest_base64(data, key)?;
        Ok(computed == hmac_base64)
    }

    /// 验证字符串的 Base64 编码 HMAC-SHA256
    ///
    /// # 参数
    /// * `data` - 要验证的消息字符串
    /// * `key` - HMAC 密钥字符串
    /// * `hmac_base64` - 期望的 Base64 格式 HMAC
    ///
    /// # 返回
    /// 如果 HMAC 匹配返回 true，否则返回 false
    pub fn verify_base64_str(data: &str, key: &str, hmac_base64: &str) -> ProtocolResult<bool> {
        Self::verify_base64(data.as_bytes(), key.as_bytes(), hmac_base64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256_digest() {
        let key = b"secret_key";
        let data = b"Hello, HMAC!";

        let result = HmacSha256Digester::digest(data, key).unwrap();
        assert_eq!(result.len(), 64); // SHA256 产生 64 个十六进制字符
        assert!(!result.is_empty());
    }

    #[test]
    fn test_hmac_sha256_digest_str() {
        let key = "secret_key";
        let data = "Hello, HMAC!";

        let result = HmacSha256Digester::digest_str(data, key).unwrap();
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_hmac_sha256_digest_raw() {
        let key = b"secret_key";
        let data = b"Hello, HMAC!";

        let result = HmacSha256Digester::digest_raw(data, key).unwrap();
        assert_eq!(result.len(), 32); // SHA256 产生 32 字节
    }

    #[test]
    fn test_hmac_sha256_verify() {
        let key = b"secret_key";
        let data = b"Hello, HMAC!";

        let hmac = HmacSha256Digester::digest(data, key).unwrap();
        assert!(HmacSha256Digester::verify(data, key, &hmac).unwrap());

        // 测试错误的 HMAC
        let wrong_hmac = "0".repeat(64);
        assert!(!HmacSha256Digester::verify(data, key, &wrong_hmac).unwrap());
    }

    #[test]
    fn test_hmac_sha256_verify_str() {
        let key = "secret_key";
        let data = "Hello, HMAC!";

        let hmac = HmacSha256Digester::digest_str(data, key).unwrap();
        assert!(HmacSha256Digester::verify_str(data, key, &hmac).unwrap());
    }

    #[test]
    fn test_hmac_sha256_verify_raw() {
        let key = b"secret_key";
        let data = b"Hello, HMAC!";

        let hmac = HmacSha256Digester::digest_raw(data, key).unwrap();
        assert!(HmacSha256Digester::verify_raw(data, key, &hmac).unwrap());

        // 测试错误的 HMAC
        let wrong_hmac = vec![0u8; 32];
        assert!(!HmacSha256Digester::verify_raw(data, key, &wrong_hmac).unwrap());
    }

    #[test]
    fn test_hmac_sha256_verify_constant_time() {
        let key = b"secret_key";
        let data = b"Hello, HMAC!";

        let hmac = HmacSha256Digester::digest_raw(data, key).unwrap();
        assert!(HmacSha256Digester::verify_constant_time(data, key, &hmac).unwrap());

        // 测试错误的 HMAC
        let wrong_hmac = vec![0u8; 32];
        assert!(!HmacSha256Digester::verify_constant_time(data, key, &wrong_hmac).unwrap());
    }

    #[test]
    fn test_hmac_sha256_digest_base64() {
        let key = b"secret_key";
        let data = b"Hello, HMAC!";

        let result = HmacSha256Digester::digest_base64(data, key).unwrap();
        assert!(!result.is_empty());

        // Base64 编码的长度应该是 44 字符 (32 字节 * 4/3，向上取整)
        assert_eq!(result.len(), 44);
    }

    #[test]
    fn test_hmac_sha256_verify_base64() {
        let key = b"secret_key";
        let data = b"Hello, HMAC!";

        let hmac = HmacSha256Digester::digest_base64(data, key).unwrap();
        assert!(HmacSha256Digester::verify_base64(data, key, &hmac).unwrap());

        // 测试错误的 HMAC
        assert!(!HmacSha256Digester::verify_base64(data, key, "wrong_hmac").unwrap());
    }

    #[test]
    fn test_hmac_sha256_different_keys() {
        let data = b"Same data";
        let key1 = b"key1";
        let key2 = b"key2";

        let hmac1 = HmacSha256Digester::digest(data, key1).unwrap();
        let hmac2 = HmacSha256Digester::digest(data, key2).unwrap();

        // 不同的密钥应该产生不同的 HMAC
        assert_ne!(hmac1, hmac2);
    }

    #[test]
    fn test_hmac_sha256_different_data() {
        let key = b"same_key";
        let data1 = b"Data 1";
        let data2 = b"Data 2";

        let hmac1 = HmacSha256Digester::digest(data1, key).unwrap();
        let hmac2 = HmacSha256Digester::digest(data2, key).unwrap();

        // 不同的数据应该产生不同的 HMAC
        assert_ne!(hmac1, hmac2);
    }

    #[test]
    fn test_hmac_sha256_known_vector() {
        // RFC 4231 测试向量
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";

        let result = HmacSha256Digester::digest(data, key).unwrap();

        // RFC 4231 中的预期结果
        let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hmac_sha256_empty_data() {
        let key = b"key";
        let data = b"";

        let result = HmacSha256Digester::digest(data, key).unwrap();
        assert_eq!(result.len(), 64);

        // 验证空数据的 HMAC
        assert!(HmacSha256Digester::verify(data, key, &result).unwrap());
    }

    #[test]
    fn test_hmac_sha256_case_insensitive_verify() {
        let key = b"key";
        let data = b"data";

        let hmac = HmacSha256Digester::digest(data, key).unwrap();
        let hmac_upper = hmac.to_uppercase();

        // 验证应该是大小写不敏感的
        assert!(HmacSha256Digester::verify(data, key, &hmac_upper).unwrap());
    }
}
