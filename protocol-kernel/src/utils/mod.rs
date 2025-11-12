use pinyin::ToPinyin;
use rand::Rng;

pub mod crc_util;
pub mod hex_util;
pub mod math_util;
pub mod timestamp_util;

// 定义字符集：大写字母(A-Z) + 小写字母(a-z) + 数字(0-9)
const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

pub fn generate_rand(len: usize) -> String {
    let mut rng = rand::rng();
    std::iter::repeat_with(|| {
        let idx = rng.random_range(0..CHARSET.len());
        CHARSET[idx] as char
    })
    .take(len)
    .collect()
}

pub fn to_pinyin(s: &str) -> String {
    let mut result: Vec<String> = Vec::new();
    let mut non_chinese_buffer = String::new();

    let pinyin_iter = s.to_pinyin();
    let mut char_iter = s.chars();

    // 同步遍历两个迭代器
    for pinyin_option in pinyin_iter {
        let original_char = char_iter.next().unwrap();

        match pinyin_option {
            Some(pinyin) => {
                if !non_chinese_buffer.is_empty() {
                    result.push(non_chinese_buffer.clone());
                    non_chinese_buffer.clear();
                }
                result.push(pinyin.plain().to_string());
            }
            None => {
                // 2. 非中文字符
                if original_char.is_alphanumeric() {
                    non_chinese_buffer.push(original_char);
                } else {
                    // 2b. 如果是空格、标点等
                    // 检查缓冲区，如果里面有 "gemini"，先将其推入结果
                    if !non_chinese_buffer.is_empty() {
                        result.push(non_chinese_buffer.clone());
                        non_chinese_buffer.clear();
                    }
                    // (我们忽略这个空格或标点符号本身)
                }
            }
        }
    }
    if !non_chinese_buffer.is_empty() {
        result.push(non_chinese_buffer);
    }

    result.join("_").trim().to_string()
}
