use protocol_base::{ProtocolResult, error::ProtocolError};
use rust_decimal::RoundingStrategy;
use rust_decimal::prelude::*;

/// 模仿 Java 的 RoundingMode，提供给外部调用者使用
#[derive(Debug, Clone, Copy)]
pub enum DecimalRoundingMode {
    /// (HALF_UP) 四舍五入
    HalfUp,
    /// (DOWN) 直接截断
    Down,
    /// (UP) 远离零
    Up,
    /// (CEILING) 趋向正无穷
    Ceiling,
    /// (FLOOR) 趋向负无穷
    Floor,
}

impl DecimalRoundingMode {
    /// 转换为 rust_decimal 库的内部策略
    fn to_strategy(self) -> RoundingStrategy {
        match self {
            DecimalRoundingMode::HalfUp => RoundingStrategy::MidpointAwayFromZero,
            DecimalRoundingMode::Down => RoundingStrategy::ToZero,
            DecimalRoundingMode::Up => RoundingStrategy::AwayFromZero,
            DecimalRoundingMode::Ceiling => RoundingStrategy::ToPositiveInfinity,
            DecimalRoundingMode::Floor => RoundingStrategy::ToNegativeInfinity,
        }
    }
}

/// (内部) 安全地将 f64 转换为高精度 Decimal
///
/// 通过 f64 -> String -> Decimal 的路径，
/// 彻底规避浮点数精度陷阱。
fn f64_to_decimal(num: f64) -> ProtocolResult<Decimal> {
    Decimal::from_str(&num.to_string())
        .map_err(|e| ProtocolError::CommonError(format!("Failed to parse f64 to Decimal: {}", e)))
}

/// (内部) 安全地将 Decimal 转换回 f64
///
/// 注意：如果 Decimal 的精度超出了 f64 的表示范围，
/// 转换 *仍然* 可能会丢失精度，但在计算 *过程* 中是无损的。
fn decimal_to_f64(dec: Decimal) -> f64 {
    // .to_f64() 在标准库中是可用的
    dec.to_f64().unwrap_or(f64::NAN)
}

/// 高精度加法 (对应 Java plus)
/// (不进行四舍五入)
pub fn plus(doubles: &[f64]) -> ProtocolResult<f64> {
    let mut result = Decimal::ZERO;
    for &a in doubles {
        result = result
            .checked_add(f64_to_decimal(a)?)
            .ok_or_else(|| ProtocolError::CommonError("Decimal addition overflow".into()))?;
    }
    Ok(decimal_to_f64(result))
}

/// 高精度减法 (对应 Java subtract)
/// (不进行四舍五入)
pub fn subtract(minuend: f64, sub: f64) -> ProtocolResult<f64> {
    let d_minuend = f64_to_decimal(minuend)?;
    let d_sub = f64_to_decimal(sub)?;

    let result = d_minuend
        .checked_sub(d_sub)
        .ok_or_else(|| ProtocolError::CommonError("Decimal subtraction overflow".into()))?;

    Ok(decimal_to_f64(result))
}

/// 高精度乘法 (对应 Java multiply)
///
/// # Arguments
/// * `scale` - 小数位数
/// * `rounding_mode` - 舍入模式
/// * `doubles` - 要相乘的 f64 数组
pub fn multiply(
    scale: u32,
    rounding_mode: DecimalRoundingMode,
    doubles: &[f64],
) -> ProtocolResult<f64> {
    let mut result = Decimal::ONE;
    for &a in doubles {
        result = result
            .checked_mul(f64_to_decimal(a)?)
            .ok_or_else(|| ProtocolError::CommonError("Decimal multiplication overflow".into()))?;
    }

    // 在 rust_decimal 中, `round_dp_with_strategy` = `setScale`
    let final_result = result.round_dp_with_strategy(scale, rounding_mode.to_strategy());
    Ok(decimal_to_f64(final_result))
}

/// 高精度除法 (对应 Java divide)
///
/// # Arguments
/// * `dividend` - 被除数
/// * `divisor` - 除数
/// * `scale` - 小数位数
/// * `rounding_mode` - 舍入模式
pub fn divide(
    dividend: f64,
    divisor: f64,
    scale: u32,
    rounding_mode: DecimalRoundingMode,
) -> ProtocolResult<f64> {
    let d_dividend = f64_to_decimal(dividend)?;
    let d_divisor = f64_to_decimal(divisor)?;

    if d_divisor.is_zero() {
        return Err(ProtocolError::CommonError("Division by zero".into()));
    }

    let result = d_dividend
        .checked_div(d_divisor)
        .ok_or_else(|| ProtocolError::CommonError("Decimal division overflow".into()))?;

    // 在 rust_decimal 中, `round_dp_with_strategy` = `setScale`
    let final_result = result.round_dp_with_strategy(scale, rounding_mode.to_strategy());
    Ok(decimal_to_f64(final_result))
}
