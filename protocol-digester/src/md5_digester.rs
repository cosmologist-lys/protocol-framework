use protocol_base::ProtocolResult;

/// MD5 加密器
pub struct Md5Digester;

impl Md5Digester {
    /// 对数据进行 MD5 加密（无盐）
    pub fn digest(data: &[u8]) -> ProtocolResult<String> {
        let digest = md5::compute(data);
        Ok(format!("{:x}", digest))
    }

    /// 对字符串进行 MD5 加密（无盐）
    pub fn digest_str(data: &str) -> ProtocolResult<String> {
        Self::digest(data.as_bytes())
    }

    /// 对数据进行带盐 MD5 加密
    pub fn digest_with_salt(data: &[u8], salt: &[u8]) -> ProtocolResult<String> {
        let mut salted_data = Vec::with_capacity(data.len() + salt.len());
        salted_data.extend_from_slice(data);
        salted_data.extend_from_slice(salt);
        Self::digest(&salted_data)
    }

    /// 对字符串进行带盐 MD5 加密
    pub fn digest_str_with_salt(data: &str, salt: &str) -> ProtocolResult<String> {
        Self::digest_with_salt(data.as_bytes(), salt.as_bytes())
    }

    /// 对数据进行带盐 MD5 加密（盐在前）
    pub fn digest_with_salt_prefix(data: &[u8], salt: &[u8]) -> ProtocolResult<String> {
        let mut salted_data = Vec::with_capacity(salt.len() + data.len());
        salted_data.extend_from_slice(salt);
        salted_data.extend_from_slice(data);
        Self::digest(&salted_data)
    }

    /// 对字符串进行带盐 MD5 加密（盐在前）
    pub fn digest_str_with_salt_prefix(data: &str, salt: &str) -> ProtocolResult<String> {
        Self::digest_with_salt_prefix(data.as_bytes(), salt.as_bytes())
    }

    /// 对数据进行带盐 MD5 加密（盐在后）
    pub fn digest_with_salt_suffix(data: &[u8], salt: &[u8]) -> ProtocolResult<String> {
        Self::digest_with_salt(data, salt)
    }

    /// 对字符串进行带盐 MD5 加密（盐在后）
    pub fn digest_str_with_salt_suffix(data: &str, salt: &str) -> ProtocolResult<String> {
        Self::digest_str_with_salt(data, salt)
    }

    /// 对数据进行多次 MD5 加密
    pub fn digest_multiple(data: &[u8], iterations: usize) -> ProtocolResult<String> {
        let mut result = Self::digest(data)?;
        for _ in 1..iterations {
            result = Self::digest(result.as_bytes())?;
        }
        Ok(result)
    }

    /// 对字符串进行多次 MD5 加密
    pub fn digest_str_multiple(data: &str, iterations: usize) -> ProtocolResult<String> {
        Self::digest_multiple(data.as_bytes(), iterations)
    }

    /// 对数据进行带盐多次 MD5 加密
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

    /// 对字符串进行带盐多次 MD5 加密
    pub fn digest_str_with_salt_multiple(
        data: &str,
        salt: &str,
        iterations: usize,
    ) -> ProtocolResult<String> {
        Self::digest_with_salt_multiple(data.as_bytes(), salt.as_bytes(), iterations)
    }

    /// 验证数据与 MD5 哈希是否匹配（无盐）
    pub fn verify(data: &[u8], hash: &str) -> ProtocolResult<bool> {
        Ok(Self::digest(data)? == hash)
    }

    /// 验证字符串与 MD5 哈希是否匹配（无盐）
    pub fn verify_str(data: &str, hash: &str) -> ProtocolResult<bool> {
        Ok(Self::digest_str(data)? == hash)
    }

    /// 验证数据与带盐 MD5 哈希是否匹配
    pub fn verify_with_salt(data: &[u8], salt: &[u8], hash: &str) -> ProtocolResult<bool> {
        Ok(Self::digest_with_salt(data, salt)? == hash)
    }

    /// 验证字符串与带盐 MD5 哈希是否匹配
    pub fn verify_str_with_salt(data: &str, salt: &str, hash: &str) -> ProtocolResult<bool> {
        Ok(Self::digest_str_with_salt(data, salt)? == hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5_digest() {
        let data = b"hello world";
        let result = Md5Digester::digest(data).unwrap();
        assert_eq!(result, "5eb63bbbe01eeed093cb22bb8f5acdc3");
    }

    #[test]
    fn test_md5_digest_str() {
        let data = "hello world";
        let result = Md5Digester::digest_str(data).unwrap();
        assert_eq!(result, "5eb63bbbe01eeed093cb22bb8f5acdc3");
    }

    #[test]
    fn test_md5_digest_with_salt() {
        let data = b"hello";
        let salt = b"world";
        let result = Md5Digester::digest_with_salt(data, salt).unwrap();
        assert_eq!(result, "fc5e038d38a57032085441e7fe7010b0");
    }

    #[test]
    fn test_md5_digest_with_salt_prefix() {
        let data = b"hello";
        let salt = b"world";
        let result = Md5Digester::digest_with_salt_prefix(data, salt).unwrap();
        assert_eq!(result, "5acd1fb6f07255681a2f6187123c0d39");
    }

    #[test]
    fn test_md5_verify() {
        let data = b"hello world";
        let hash = "5eb63bbbe01eeed093cb22bb8f5acdc3";
        assert!(Md5Digester::verify(data, hash).unwrap());
    }

    #[test]
    fn test_md5_verify_with_salt() {
        let data = b"hello";
        let salt = b"world";
        let hash = "fc5e038d38a57032085441e7fe7010b0";
        assert!(Md5Digester::verify_with_salt(data, salt, hash).unwrap());
    }

    #[test]
    fn test_md5_digest_multiple() {
        let data = b"hello";
        let result = Md5Digester::digest_multiple(data, 2).unwrap();
        assert_eq!(result, "69a329523ce1ec88bf63061863d9cb14");
    }

    #[test]
    fn test_md5_digest_with_salt_multiple() {
        let data = b"hello";
        let salt = b"world";
        let result = Md5Digester::digest_with_salt_multiple(data, salt, 2).unwrap();
        assert_eq!(result, "a11ee4c2150caf49670ad114b7fdc735");
    }
}
