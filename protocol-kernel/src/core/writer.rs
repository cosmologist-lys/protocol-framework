use std::collections::HashMap;

use protocol_base::{ProtocolError, ProtocolResult};

use crate::{
    core::parts::{placeholder::PlaceHolder, rawfield::Rawfield},
    utils::{crc_util, hex_util},
    ReportField,
};

#[derive(Debug, Default)]
pub struct Writer {
    buffer: Vec<u8>,
    fields: Vec<Rawfield>,
    placeholders: HashMap<String, PlaceHolder>, // 占位符(标记名称，起始位置，终止位置)
}

impl Writer {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            fields: Vec::new(),
            placeholders: HashMap::new(),
        }
    }

    /// (非消耗) 获取对当前 buffer 的引用
    pub fn buffer(&self) -> ProtocolResult<&[u8]> {
        Ok(&self.buffer)
    }

    /// (非消耗) 获取对当前 fields 的引用
    pub fn fields(&self) -> ProtocolResult<&Vec<Rawfield>> {
        Ok(&self.fields)
    }

    pub fn to_report_fields(&self) -> ProtocolResult<Vec<ReportField>> {
        let fields = self.fields.clone();
        let r: Vec<ReportField> = fields.into_iter().map(|f| f.to_report_field()).collect();
        Ok(r)
    }

    pub fn full_hex(self) -> ProtocolResult<String> {
        let bytes = self.buffer()?;
        hex_util::bytes_to_hex(bytes)
    }

    pub fn capacity(&self) -> ProtocolResult<usize> {
        Ok(self.buffer.capacity())
    }

    pub fn placeholders_tags(&self) -> ProtocolResult<Vec<&str>> {
        Ok(self.placeholders.keys().map(|s| s.as_str()).collect())
    }

    pub fn into_placeholder_by_tag(&mut self, tag: &str) -> ProtocolResult<PlaceHolder> {
        self.placeholders
            .remove(tag)
            .ok_or_else(|| ProtocolError::CommonError("未找到标签为 '{tag}' 的占位符".into()))
    }

    /// 核心写入方法：调用一个闭包来生成 Rawfield，然后写入其字节
    ///
    /// 闭包 `translator` 负责“创造”一个 Rawfield。
    /// Writer 会自动将该 Rawfield 的 hex 值转换为字节并追加到缓冲区。
    pub fn write<F>(&mut self, translator: F) -> ProtocolResult<&mut Self>
    where
        F: FnOnce() -> ProtocolResult<Rawfield>,
    {
        // 1. 调用闭包，获取“翻译”结果
        let field = translator()?;

        // 2. 从 Rawfield 中提取字节
        let bytes_to_write = field.bytes.clone();

        // 3. 追加字节到缓冲区
        self.buffer.extend_from_slice(&bytes_to_write);

        // 4. 存储翻译记录
        self.fields.push(field);

        Ok(self)
    }

    /// 便捷方法：写入
    pub fn write_bytes(
        &mut self,
        title: &str,
        data: &[u8],
        value: &str,
    ) -> ProtocolResult<&mut Self> {
        let field = Rawfield::new(data, title.into(), value.into()); //
        self.buffer.extend_from_slice(data);
        self.fields.push(field);
        Ok(self)
    }

    /// 写入 N 字节的占位符 (默认为 0x00)，并返回其在缓冲区中的起始位置。
    ///
    /// 这用于稍后 "回填" 动态数据 (如总长度或 CRC)。
    ///
    /// # Arguments
    /// * `byte_len` - 要写入的占位字节的长度。
    ///
    /// # Returns
    /// * `Ok(usize)` - 占位符在 `buffer` 中的起始字节位置 (pos)。
    pub fn write_placeholder(&mut self, tag: &str, byte_len: usize) -> ProtocolResult<&mut Self> {
        // 1. 记住当前位置 (即写入前的 buffer 长度)
        let start_pos = self.buffer.len();

        if byte_len == 0 {
            return Err(ProtocolError::ValidationFailed(
                "Placeholder byte_len must be greater than 0".into(),
            ));
        }

        // 2. 创建占位符字节
        let placeholder_bytes = vec![0u8; byte_len];

        let end_pos = start_pos + byte_len;
        let fields_pos = self.fields.len();
        let placeholder = PlaceHolder::new(tag, fields_pos, start_pos, end_pos);

        // 3. 写入占位符 (使用已有的 write_bytes 逻辑)
        self.buffer.extend_from_slice(&placeholder_bytes);
        self.placeholders.insert(tag.into(), placeholder);

        // 4. 返回写入的起始位置
        Ok(self)
    }

    /// 在缓冲区的指定位置“覆写” (Patch/Overwrite) 字节。
    ///
    /// 这个方法 *不会* 改变缓冲区的总长度，它只是替换数据。
    /// 它也 *不会* 更新 `fields` 列表，因此 `fields` 日志可能会“过时”
    /// (例如，日志里显示 "0000"，但缓冲区里是真实长度)。
    /// 这是“回填”场景下可接受的取舍。
    ///
    /// # Returns
    /// * `Ok(&mut Self)` - 链式调用。
    ///
    /// # Errors
    /// * `ProtocolError::ValidationFailed` - 如果 `pos + data.len()` 超出了缓冲区的总长度。
    pub fn rewrite_placeholder(
        &mut self,
        placeholder_tag: &str,
        title: &str,
        bytes: &[u8],
        hex: &str,
    ) -> ProtocolResult<&mut Self> {
        // 1. 查找并消耗占位符
        let placeholder = self.into_placeholder_by_tag(placeholder_tag)?;

        // 2. 检查数据长度是否与占位符长度完全一致
        let expected_len = placeholder.capacity();
        if bytes.len() != expected_len {
            return Err(ProtocolError::ValidationFailed(format!(
                "Data length mismatch for placeholder '{placeholder_tag}'. Expected {expected_len} bytes, but got {}",
                bytes.len()
            )));
        }

        // 3. 获取缓冲区的可变切片
        let dest_slice = &mut self.buffer[placeholder.start_index..placeholder.end_index];

        // 4. 执行覆写
        dest_slice.copy_from_slice(bytes);

        // 5. 创建 Rawfield
        let field = Rawfield::new(bytes, title.into(), hex.into());

        // 6. 将 Rawfield 插入到 fields 列表的正确位置
        self.fields.insert(placeholder.pos, field);

        Ok(self)
    }

    /// 读取起始位置->终止位置的切片。
    fn get_buffer_slice(&self, start_index: usize, end_index: isize) -> ProtocolResult<&[u8]> {
        let total = self.buffer.len();

        // 1. 解析 end_index
        let ei = if end_index >= 0 {
            end_index as usize
        } else {
            // 负数，从 total 倒数
            match (total as isize).checked_add(end_index) {
                Some(index) if index >= 0 => index as usize,
                _ => {
                    return Err(ProtocolError::ValidationFailed(format!(
                        "end_index {} is out of bounds",
                        end_index
                    )));
                }
            }
        };

        // 2. 边界安全检查
        if ei > total {
            return Err(ProtocolError::ValidationFailed(format!(
                "end_index {} (resolved to {}) is out of bounds ({})",
                end_index, ei, total
            )));
        }

        if start_index > ei {
            return Err(ProtocolError::ValidationFailed(format!(
                "start_index {} is greater than end_index {}",
                start_index, ei
            )));
        }

        // 3. 安全地返回切片 (零拷贝)
        Ok(&self.buffer[start_index..ei])
    }

    /// 计算指定范围内字节的 CRC，并将结果“回填”到占位符。
    ///
    /// # Arguments
    /// * `crc_type` - 要使用的 CRC 算法 (例如 CrcType::Crc16Modbus)。
    /// * `start_index` - 缓冲区中用于计算的起始字节索引 (包含)。
    /// * `end_index` - 缓冲区中用于计算的结束字节索引 (不包含)。
    /// * 如果为负数 (例如 -2)，则从末尾计算 (例如 buffer.len() - 2)。
    /// * `placeholder_tag` - 要“回填”的占位符的 tag。
    /// * `swap` - 是否翻转CRC字节。
    /// * 并返回 `Vec<u8>` (例如 `|crc| Ok(crc.to_be_bytes().to_vec())`)。
    ///
    pub fn write_crc<F>(
        &mut self,
        crc_type: protocol_base::definitions::defi::CrcType,
        start_index: usize,
        end_index: isize,
        placeholder_tag: &str,
        swap: bool,
    ) -> ProtocolResult<&mut Self> {
        // 1. 获取需要计算 CRC 的数据切片
        // (注意：传入 self.buffer.len() 作为总长)
        let data_to_check = self.get_buffer_slice(start_index, end_index)?;

        // 2. 计算 CRC
        let crc_value = crc_util::calculate_from_bytes(crc_type, data_to_check)?;
        let final_crc_value = if swap {
            crc_value.to_le_bytes()
        } else {
            crc_value.to_be_bytes()
        };
        let crc_hex = hex_util::bytes_to_hex(&final_crc_value)?;

        // 3. 回填字节
        self.rewrite_placeholder(placeholder_tag, "crc", &final_crc_value, crc_hex.as_str())?;

        Ok(self)
    }
}
