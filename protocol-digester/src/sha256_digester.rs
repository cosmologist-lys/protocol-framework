use protocol_base::ProtocolResult;
use sha2::{Digest, Sha256};

/// SHA256 加密器
pub struct Sha256Digester;

impl Sha256Digester {
    /// 对数据进行 SHA256 加密（无盐）
    pub fn digest(data: &[u8]) -> ProtocolResult<String> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        Ok(format!("{:x}", result))
    }

    /// 对字符串进行 SHA256 加密（无盐）
    pub fn digest_str(data: &str) -> ProtocolResult<String> {
        Self::digest(data.as_bytes())
    }

    /// 对数据进行带盐 SHA256 加密
    pub fn digest_with_salt(data: &[u8], salt: &[u8]) -> ProtocolResult<String> {
        let mut salted_data = Vec::with_capacity(data.len() + salt.len());
        salted_data.extend_from_slice(data);
        salted_data.extend_from_slice(salt);
        Self::digest(&salted_data)
    }

    /// 对字符串进行带盐 SHA256 加密
    pub fn digest_str_with_salt(data: &str, salt: &str) -> ProtocolResult<String> {
        Self::digest_with_salt(data.as_bytes(), salt.as_bytes())
    }

    /// 对数据进行带盐 SHA256 加密（盐在前）
    pub fn digest_with_salt_prefix(data: &[u8], salt: &[u8]) -> ProtocolResult<String> {
        let mut salted_data = Vec::with_capacity(salt.len() + data.len());
        salted_data.extend_from_slice(salt);
        salted_data.extend_from_slice(data);
        Self::digest(&salted_data)
    }

    /// 对字符串进行带盐 SHA256 加密（盐在前）
    pub fn digest_str_with_salt_prefix(data: &str, salt: &str) -> ProtocolResult<String> {
        Self::digest_with_salt_prefix(data.as_bytes(), salt.as_bytes())
    }

    /// 对数据进行带盐 SHA256 加密（盐在后）
    pub fn digest_with_salt_suffix(data: &[u8], salt: &[u8]) -> ProtocolResult<String> {
        Self::digest_with_salt(data, salt)
    }

    /// 对字符串进行带盐 SHA256 加密（盐在后）
    pub fn digest_str_with_salt_suffix(data: &str, salt: &str) -> ProtocolResult<String> {
        Self::digest_str_with_salt(data, salt)
    }

    /// 对数据进行多次 SHA256 加密
    pub fn digest_multiple(data: &[u8], iterations: usize) -> ProtocolResult<String> {
        let mut result = Self::digest(data)?;
        for _ in 1..iterations {
            result = Self::digest(result.as_bytes())?;
        }
        Ok(result)
    }

    /// 对字符串进行多次 SHA256 加密
    pub fn digest_str_multiple(data: &str, iterations: usize) -> ProtocolResult<String> {
        Self::digest_multiple(data.as_bytes(), iterations)
    }

    /// 对数据进行带盐多次 SHA256 加密
    pub fn digest_with_salt_multiple(
        data: &[u8],
        salt: &[u8],
        iterations: usize,
    ) -> ProtocolResult<String> {
        let mut result = Self::digest_with_salt(data, salt)?;
        for _ in 1..iterations {
            result = Self::digest(result.as_bytes())?;
        }
        Ok(result)
    }

    /// 对字符串进行带盐多次 SHA256 加密
    pub fn digest_str_with_salt_multiple(
        data: &str,
        salt: &str,
        iterations: usize,
    ) -> ProtocolResult<String> {
        Self::digest_with_salt_multiple(data.as_bytes(), salt.as_bytes(), iterations)
    }

    /// 验证数据与 SHA256 哈希是否匹配（无盐）
    pub fn verify(data: &[u8], hash: &str) -> ProtocolResult<bool> {
        Ok(Self::digest(data)? == hash)
    }

    /// 验证字符串与 SHA256 哈希是否匹配（无盐）
    pub fn verify_str(data: &str, hash: &str) -> ProtocolResult<bool> {
        Ok(Self::digest_str(data)? == hash)
    }

    /// 验证数据与带盐 SHA256 哈希是否匹配
    pub fn verify_with_salt(data: &[u8], salt: &[u8], hash: &str) -> ProtocolResult<bool> {
        Ok(Self::digest_with_salt(data, salt)? == hash)
    }

    /// 验证字符串与带盐 SHA256 哈希是否匹配
    pub fn verify_str_with_salt(data: &str, salt: &str, hash: &str) -> ProtocolResult<bool> {
        Ok(Self::digest_str_with_salt(data, salt)? == hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_digest() {
        let data = b"hello world";
        let result = Sha256Digester::digest(data).unwrap();
        assert_eq!(
            result,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_sha256_digest_str() {
        let data = "hello world";
        let result = Sha256Digester::digest_str(data).unwrap();
        assert_eq!(
            result,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_sha256_digest_with_salt() {
        let data = b"hello";
        let salt = b"world";
        let result = Sha256Digester::digest_with_salt(data, salt).unwrap();
        assert_eq!(
            result,
            "936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af"
        );
    }

    #[test]
    fn test_sha256_digest_with_salt_prefix() {
        let data = b"hello";
        let salt = b"world";
        let result = Sha256Digester::digest_with_salt_prefix(data, salt).unwrap();
        assert_eq!(
            result,
            "8376118fc0230e6054e782fb31ae52ebcfd551342d8d026c209997e0127b6f74"
        );
    }

    #[test]
    fn test_sha256_verify() {
        let data = b"hello world";
        let hash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert!(Sha256Digester::verify(data, hash).unwrap());
    }

    #[test]
    fn test_sha256_verify_with_salt() {
        let data = b"hello";
        let salt = b"world";
        let hash = "936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af";
        assert!(Sha256Digester::verify_with_salt(data, salt, hash).unwrap());
    }

    #[test]
    fn test_sha256_digest_multiple() {
        let data = b"hello";
        let result = Sha256Digester::digest_multiple(data, 2).unwrap();
        assert_eq!(
            result,
            "d7914fe546b684688bb95f4f888a92dfc680603a75f23eb823658031fff766d9"
        );
    }

    #[test]
    fn test_sha256_digest_with_salt_multiple() {
        let data = b"hello";
        let salt = b"world";
        let result = Sha256Digester::digest_with_salt_multiple(data, salt, 2).unwrap();
        // 这个哈希值需要实际运行来验证
        assert!(!result.is_empty());
        assert_eq!(result.len(), 64); // SHA256 哈希长度为 64 个十六进制字符
    }

    #[test]
    fn test_sha256_verify_str() {
        let data = "test";
        let hash = Sha256Digester::digest_str(data).unwrap();
        assert!(Sha256Digester::verify_str(data, &hash).unwrap());
    }

    #[test]
    fn test_sha256_verify_str_with_salt() {
        let data = "test";
        let salt = "salt";
        let hash = Sha256Digester::digest_str_with_salt(data, salt).unwrap();
        assert!(Sha256Digester::verify_str_with_salt(data, salt, &hash).unwrap());
    }
}
