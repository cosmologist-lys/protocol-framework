use chrono::Local;

use crate::utils::hex_util;
use protocol_base::{
    error::{hex_error::HexError, ProtocolError},
    ProtocolResult,
};

/// 定义了 BCD 时间戳的格式化类型
pub enum TimestampType {
    Year,                   //yyyy
    YearMonth,              //yyyy-MM
    YearMonthDay,           //yyyy-MM-dd
    YearMonthDayHour,       //yyyy-MM-dd HH
    YearMonthDayHourMin,    //yyyy-MM-dd HH:mm
    YearMonthDayHourMinSec, //yyyy-MM-dd HH:mm:ss
    HourMinSec,             //HH:mm:ss
    YyyyMmDdHHmmss,         // yyyymmddHHmmss (4字节年)
    YyyyMmDd,               // yyyymmdd (4字节年)
    HHmmss,                 // HHmmss
    YyMmDdHHmmss,           // yymmddHHmmss (2字节年)
    YyMmDd,                 // yymmdd (2字节年)
}

const YEAR_PREFIX: &str = "20";

/// 核心转换函数：将 BCD 字节切片按指定格式转换为日期字符串
///
/// # Arguments
/// * `bcd_bytes` - BCD 格式的字节 (例如 `&[0x23, 0x05, 0x15]`)
/// * `timestamp_type` - 期望的时间戳格式
///
/// # Returns
/// * `ProtocolResult<String>` - 格式化后的字符串 (例如 "2023-05-15")
pub fn convert(bcd_bytes: &[u8], timestamp_type: TimestampType) -> ProtocolResult<String> {
    // 1. 将 BCD 字节转换为 BCD 字符串
    // (例如 &[0x23, 0x05, 0x15] -> "230515")
    let bcd_str = hex_util::bytes_to_hex(bcd_bytes)?;

    // 2. 校验是否为 BCD (全数字)
    if !hex_util::is_bcd(&bcd_str) {
        return Err(ProtocolError::HexError(HexError::NotBcd(bcd_str)));
    }

    // 3. 规范化：如果 BCD 字符串以 "20" 开头 (例如 "20230515")，
    //    则将其剥离为 "230515"，以便后续函数统一处理 "yy" 格式。
    //
    let ts = match bcd_str.starts_with(YEAR_PREFIX) {
        true => &bcd_str[YEAR_PREFIX.len()..],
        false => &bcd_str,
    };

    // 4. 根据类型分派给辅助函数
    let result = match timestamp_type {
        TimestampType::Year => convert_to_year(ts),
        TimestampType::YearMonth => convert_to_year_month(ts),
        TimestampType::YearMonthDay => convert_to_year_month_day(ts),
        TimestampType::YearMonthDayHour => convert_to_year_month_day_hour(ts),
        TimestampType::YearMonthDayHourMin => convert_to_year_month_day_hour_min(ts),
        TimestampType::YearMonthDayHourMinSec => convert_to_year_month_day_hour_min_sec(ts),
        TimestampType::HourMinSec => convert_to_hour_min_sec(ts),

        TimestampType::YyyyMmDdHHmmss => convert_to_yyyymmddhhmmss(ts),
        TimestampType::YyyyMmDd => convert_to_yyyymmdd(ts),
        TimestampType::HHmmss => convert_to_hhmmss(ts),
        TimestampType::YyMmDdHHmmss => convert_to_yymmddhhmmss(ts),
        TimestampType::YyMmDd => convert_to_yymmdd(ts),
    };

    Ok(result)
}

// --- 公共 API 别名 ---

pub fn now_to_timestamp(timestamp_type: TimestampType) -> ProtocolResult<String> {
    // 2. 获取当前本地时间
    let now = Local::now();

    // 3. 根据类型选择 chrono 的格式化字符串
    let format_string = match timestamp_type {
        TimestampType::Year => "%Y",
        TimestampType::YearMonth => "%Y-%m",
        TimestampType::YearMonthDay => "%Y-%m-%d",
        TimestampType::YearMonthDayHour => "%Y-%m-%d %H",
        TimestampType::YearMonthDayHourMin => "%Y-%m-%d %H:%M",
        TimestampType::YearMonthDayHourMinSec => "%Y-%m-%d %H:%M:%S",
        TimestampType::HourMinSec => "%H:%M:%S",
        TimestampType::YyyyMmDdHHmmss => "%Y%m%d%H%M%S",
        TimestampType::YyyyMmDd => "%Y%m%d",
        TimestampType::HHmmss => "%H%M%S",
        TimestampType::YyMmDdHHmmss => "%y%m%d%H%M%S", // %y 代表两位数年份
        TimestampType::YyMmDd => "%y%m%d",             // %y 代表两位数年份
    };

    // 4. 格式化并返回
    // chrono 的 format 不会轻易失败，除非格式字符串本身有问题（这里不会）
    Ok(now.format(format_string).to_string())
}

pub fn to_year(bcd_bytes: &[u8]) -> ProtocolResult<String> {
    convert(bcd_bytes, TimestampType::Year)
}
pub fn to_year_month(bcd_bytes: &[u8]) -> ProtocolResult<String> {
    convert(bcd_bytes, TimestampType::YearMonth)
}
pub fn to_year_month_day(bcd_bytes: &[u8]) -> ProtocolResult<String> {
    convert(bcd_bytes, TimestampType::YearMonthDay)
}
pub fn to_year_month_day_hour(bcd_bytes: &[u8]) -> ProtocolResult<String> {
    convert(bcd_bytes, TimestampType::YearMonthDayHour)
}
pub fn to_year_month_day_hour_min(bcd_bytes: &[u8]) -> ProtocolResult<String> {
    convert(bcd_bytes, TimestampType::YearMonthDayHourMin)
}
pub fn to_year_month_day_hour_min_sec(bcd_bytes: &[u8]) -> ProtocolResult<String> {
    convert(bcd_bytes, TimestampType::YearMonthDayHourMinSec)
}
pub fn to_hour_min_sec(bcd_bytes: &[u8]) -> ProtocolResult<String> {
    convert(bcd_bytes, TimestampType::HourMinSec)
}

pub fn to_yyyymmddhhmmss(bcd_bytes: &[u8]) -> ProtocolResult<String> {
    convert(bcd_bytes, TimestampType::YyyyMmDdHHmmss)
}
pub fn to_yyyymmdd(bcd_bytes: &[u8]) -> ProtocolResult<String> {
    convert(bcd_bytes, TimestampType::YyyyMmDd)
}
pub fn to_hhmmss(bcd_bytes: &[u8]) -> ProtocolResult<String> {
    convert(bcd_bytes, TimestampType::HHmmss)
}
pub fn to_yymmddhhmmss(bcd_bytes: &[u8]) -> ProtocolResult<String> {
    convert(bcd_bytes, TimestampType::YyMmDdHHmmss)
}
pub fn to_yymmdd(bcd_bytes: &[u8]) -> ProtocolResult<String> {
    convert(bcd_bytes, TimestampType::YyMmDd)
}

// 转换 "yymmddHHmmss" -> "yyyymmddHHmmss"
fn convert_to_yyyymmddhhmmss(timestamp: &str) -> String {
    if timestamp.len() >= 12 {
        let yy = &timestamp[0..2];
        let rest = &timestamp[2..12]; // mmddHHmmss
        format!("{}{}{}", YEAR_PREFIX, yy, rest)
    } else {
        timestamp.to_string() // 长度不足，返回原样
    }
}

// 转换 "yymmdd" -> "yyyymmdd"
fn convert_to_yyyymmdd(timestamp: &str) -> String {
    if timestamp.len() >= 6 {
        let yy = &timestamp[0..2];
        let rest = &timestamp[2..6]; // mmdd
        format!("{}{}{}", YEAR_PREFIX, yy, rest)
    } else {
        timestamp.to_string()
    }
}

// 转换 "HHmmss" -> "HHmmss" (直接截取或返回原样)
fn convert_to_hhmmss(timestamp: &str) -> String {
    if timestamp.len() >= 6 {
        timestamp[0..6].to_string()
    } else {
        timestamp.to_string()
    }
}

// 转换 "yymmddHHmmss" -> "yymmddHHmmss" (直接截取或返回原样)
fn convert_to_yymmddhhmmss(timestamp: &str) -> String {
    if timestamp.len() >= 12 {
        timestamp[0..12].to_string()
    } else {
        timestamp.to_string()
    }
}

// 转换 "yymmdd" -> "yymmdd" (直接截取或返回原样)
fn convert_to_yymmdd(timestamp: &str) -> String {
    if timestamp.len() >= 6 {
        timestamp[0..6].to_string()
    } else {
        timestamp.to_string()
    }
}

// --- 私有辅助函数 ---

fn convert_to_year(timestamp: &str) -> String {
    if timestamp.len() >= 2 {
        let yy = &timestamp[0..2];
        format!("{}{}", YEAR_PREFIX, yy)
    } else {
        timestamp.to_string()
    }
}

fn convert_to_year_month(timestamp: &str) -> String {
    if timestamp.len() >= 4 {
        let yy = &timestamp[0..2];
        let month = &timestamp[2..4];
        format!("{}{}-{}", YEAR_PREFIX, yy, month)
    } else {
        timestamp.to_string()
    }
}

fn convert_to_year_month_day(timestamp: &str) -> String {
    if timestamp.len() >= 6 {
        let yy = &timestamp[0..2];
        let month = &timestamp[2..4];
        let day = &timestamp[4..6];
        format!("{}{}-{}-{}", YEAR_PREFIX, yy, month, day)
    } else {
        timestamp.to_string()
    }
}

fn convert_to_year_month_day_hour(timestamp: &str) -> String {
    if timestamp.len() >= 8 {
        let yy = &timestamp[0..2];
        let month = &timestamp[2..4];
        let day = &timestamp[4..6];
        let hour = &timestamp[6..8];
        format!("{}{}-{}-{} {}", YEAR_PREFIX, yy, month, day, hour)
    } else {
        timestamp.to_string()
    }
}

fn convert_to_year_month_day_hour_min(timestamp: &str) -> String {
    if timestamp.len() >= 10 {
        let yy = &timestamp[0..2];
        let month = &timestamp[2..4];
        let day = &timestamp[4..6];
        let hour = &timestamp[6..8];
        let minute = &timestamp[8..10];
        format!(
            "{}{}-{}-{} {}:{}",
            YEAR_PREFIX, yy, month, day, hour, minute
        )
    } else {
        timestamp.to_string()
    }
}

fn convert_to_year_month_day_hour_min_sec(timestamp: &str) -> String {
    if timestamp.len() >= 12 {
        let yy = &timestamp[0..2];
        let month = &timestamp[2..4];
        let day = &timestamp[4..6];
        let hour = &timestamp[6..8];
        let minute = &timestamp[8..10];
        let second = &timestamp[10..12];
        format!(
            "{}{}-{}-{} {}:{}:{}",
            YEAR_PREFIX, yy, month, day, hour, minute, second
        )
    } else {
        timestamp.to_string()
    }
}

fn convert_to_hour_min_sec(timestamp: &str) -> String {
    if timestamp.len() >= 6 {
        let hour = &timestamp[0..2];
        let min = &timestamp[2..4];
        let sec = &timestamp[4..6];
        format!("{}:{}:{}", hour, min, sec)
    } else {
        timestamp.to_string()
    }
}
