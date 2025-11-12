// 内部辅助宏，用于简化整数类型的转换和缩放逻辑
#[macro_export]
macro_rules! handle_int {
    ($type:ty, $len:expr, $bytes:expr, $scale:expr) => {{
        // 1. 检查长度
        if $bytes.len() != $len {
            return Err(ProtocolError::ValidationFailed(format!(
                "Invalid byte length for {}. Expected {}, got {}",
                stringify!($type),
                $len,
                $bytes.len()
            )));
        }
        // 2. 从大端字节转换
        let value = <$type>::from_be_bytes($bytes.try_into().unwrap());
        // 3. 转换为f64，准备缩放
        let value_f64 = value as f64;
        // 4. 执行缩放 (如果需要)
        if $scale != 1.0 && $scale != 0.0 {
            // 假设 scale=1.0 表示不缩放
            let scaled_value =
                math_util::multiply(6, DecimalRoundingMode::HalfUp, &[value_f64, $scale])?;
            Ok(scaled_value.to_string())
        } else if $scale == 0.0 {
            Err(ProtocolError::ValidationFailed(
                "Scale factor cannot be zero.".to_string(),
            ))
        } else {
            // 不缩放，直接转字符串
            Ok(value.to_string())
        }
    }};
}

// 内部辅助宏，用于简化整数类型的编码逻辑（从字符串到字节）
#[macro_export]
macro_rules! handle_int_encode {
    ($type:ty, $len:expr, $input:expr, $scale:expr) => {{
        // 1. 解析输入字符串为f64
        let parsed_value: f64 = $input.parse().map_err(|_| {
            ProtocolError::ValidationFailed(format!("Failed to parse input '{}' as f64", $input))
        })?;

        // 2. 执行反缩放（如果需要）
        let final_value = if $scale != 1.0 && $scale != 0.0 {
            // 假设 scale=1.0 表示不缩放
            math_util::divide(parsed_value, $scale, 6, DecimalRoundingMode::HalfUp)?
        } else if $scale == 0.0 {
            return Err(ProtocolError::ValidationFailed(
                "Scale factor cannot be zero.".to_string(),
            ));
        } else {
            parsed_value
        };

        // 3. 转换为目标整数类型
        let int_value: $type = final_value as $type;

        // 4. 转换为大端字节
        let bytes = int_value.to_be_bytes();

        Ok(bytes.to_vec())
    }};
}
