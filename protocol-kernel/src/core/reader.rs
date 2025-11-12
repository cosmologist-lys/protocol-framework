use protocol_base::{ProtocolError, ProtocolResult};

use crate::{
    core::parts::rawfield::Rawfield,
    utils::{crc_util, hex_util},
    ReportField,
};

/// 状态化的字节读取器，用于解析并收集 `Rawfield`。
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buffer: &'a [u8], // 借用原始报文，零拷贝读取
    pos: usize,       // 头部游标 (从0开始, 向前推进)
    sop: usize,       // 尾部游标 (排他性, 从len()开始, 向后推进)
    total: usize,
    fields: Vec<Rawfield>,           // 收集所有解析出的字段
    current_field: Option<Rawfield>, // 当前正在解析的字段
}

impl<'a> Reader<'a> {
    /// 用一个完整的报文字节数组创建一个新的Reader
    pub fn new(buffer: &'a [u8]) -> Self {
        Self {
            buffer,
            pos: 0,
            sop: buffer.len(), // 初始sop指向缓冲区的末尾 (排他性)
            total: buffer.len(),
            fields: Vec::new(),
            current_field: None,
        }
    }
    /// 返回总字节数
    pub fn total_len(&self) -> usize {
        self.buffer.len()
    }

    /// 内部安全检查：确保[pos..sop]之间还有`len`个字节可读
    fn check_remaining(&self, len: usize) -> ProtocolResult<()> {
        let remaining = self.remaining_len();
        if remaining < len {
            Err(ProtocolError::InputTooShort {
                needed: len,
                available: remaining,
            })
        } else {
            Ok(())
        }
    }

    /// 检查游标是否重叠
    fn check_overlap(&self) -> ProtocolResult<()> {
        if self.pos > self.sop {
            Err(ProtocolError::ValidationFailed(
                "Reader cursors overlapped".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    pub fn get_current_field_cloned(&self) -> ProtocolResult<Option<Rawfield>> {
        if self.current_field.is_some() {
            let cloned = self.current_field.clone();
            Ok(cloned)
        } else {
            Ok(None)
        }
    }

    pub fn set_current_field(&mut self, field: Rawfield) -> ProtocolResult<()> {
        self.fields.push(field.clone());
        self.current_field = Some(field);
        Ok(())
    }

    /// 返回剩余未读字节的数量 (pos 和 sop 之间的距离)
    pub fn remaining_len(&self) -> usize {
        self.sop.saturating_sub(self.pos)
    }

    pub fn to_report_fields(&self) -> ProtocolResult<Vec<ReportField>> {
        let fields = self.fields.clone();
        let r: Vec<ReportField> = fields.into_iter().map(|f| f.to_report_field()).collect();
        Ok(r)
    }

    /// 核心功能5: (CRC专用) 获取当前游标之间的所有数据
    /// (这个方法*不*移动游标，仅用于CRC计算)
    pub fn read_between_pos_to_sop_not_move(&self) -> ProtocolResult<&[u8]> {
        self.check_overlap()?;
        Ok(&self.buffer[..self.sop]) // 从0到sop (排他)
    }

    /// 1. 读取n个字节(大端) -> 返回这n个字节的数组 (副本) (并使游标前进 n)
    pub fn read_bytes(&mut self, len: usize) -> ProtocolResult<Vec<u8>> {
        self.check_remaining(len)?;
        let slice = &self.buffer[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice.to_vec()) // to_vec() 创建一个副本
    }

    /// 2. 读取n个字节并且按照小端格式 -> 返回这n个字节按照小端排列之后的数组 (副本) (并使游标前进 n)
    pub fn read_bytes_le(&mut self, len: usize) -> ProtocolResult<Vec<u8>> {
        self.check_remaining(len)?;
        let slice = &self.buffer[self.pos..self.pos + len];
        self.pos += len;

        let mut data = slice.to_vec(); // 创建副本
        data.reverse(); // 反转字节顺序
        Ok(data)
    }

    /// 2. 读取剩余字节 -> 返回剩余字节的数组 (副本) (并使游标前进到结束位置)
    pub fn read_remaining(&mut self) -> ProtocolResult<Vec<u8>> {
        let slice = &self.buffer[self.pos..self.sop];
        self.pos = self.sop;
        Ok(slice.to_vec()) // to_vec() 创建一个副本
    }

    pub fn read_and_translate_remaining<F>(&mut self, translator: F) -> ProtocolResult<&mut Self>
    where
        F: FnOnce(&[u8]) -> ProtocolResult<Rawfield>,
    {
        let remaining_bytes = self.read_remaining()?;
        let raw_field = translator(&remaining_bytes)?;
        self.current_field = Some(raw_field.clone());
        // 3. 创建并存储 Rawfield
        self.fields.push(raw_field);
        Ok(self)
    }

    /// 3. 读取n个字节(大端)，并且进行翻译 -> 返回Reader自身 (用于链式调用)
    pub fn read_and_translate_head<F>(
        &mut self,
        len: usize,
        translator: F,
    ) -> ProtocolResult<&mut Self>
    where
        // 翻译函数接收原始字节切片，返回一个翻译结果
        F: FnOnce(&[u8]) -> ProtocolResult<Rawfield>,
    {
        // 1. 检查并获取原始字节切片 (零拷贝)
        self.check_remaining(len)?;
        let raw_bytes = &self.buffer[self.pos..self.pos + len];

        // 2. 调用翻译闭包
        let raw_field = translator(raw_bytes)?;
        self.current_field = Some(raw_field.clone());
        // 3. 创建并存储 Rawfield
        self.fields.push(raw_field);

        // 4. 移动游标
        self.pos += len;

        // 5. 返回 &mut self 以便链式调用
        Ok(self)
    }

    /// 核心功能2: 从尾部(sop)读取n个字节，并且进行翻译
    /// (注意：是从后往前读)
    pub fn read_and_translate_tail<F>(
        &mut self,
        len: usize,
        translator: F,
    ) -> ProtocolResult<&mut Self>
    where
        F: FnOnce(&[u8]) -> ProtocolResult<Rawfield>,
    {
        // 1. 检查总剩余空间
        self.check_remaining(len)?;
        // 2. 检查游标是否会重叠
        self.check_overlap()?;

        // 3. 计算并获取尾部切片 (使用排他性约定)
        let new_sop = self.sop - len;
        let raw_bytes = &self.buffer[new_sop..self.sop];

        // 4. 调用翻译
        let raw_field = translator(raw_bytes)?;
        self.current_field = Some(raw_field.clone());
        self.fields.push(raw_field);

        // 5. 推进(回退)尾部游标
        self.sop = new_sop;

        Ok(self)
    }

    pub fn read_and_translate_crc(
        &mut self,
        len: usize,
        crc_mode: protocol_base::definitions::defi::CrcType,
        crc_start_pos: usize,
        crc_end_pos: isize,
    ) -> ProtocolResult<&mut Self> {
        // 1. 检查总剩余空间
        self.check_remaining(len)?;
        // 2. 检查游标是否会重叠
        self.check_overlap()?;

        // 3. 计算并获取尾部切片 (使用排他性约定)
        let new_sop = self.sop - len;
        let crc_bytes = &self.buffer[new_sop..self.sop];
        let crc_hex = hex_util::bytes_to_hex(crc_bytes)?;

        // 4. 计算crc并且进行比较
        let expected_crc_bytes = self.read_by_index_not_move(crc_start_pos, crc_end_pos)?;
        let calculated_crc_bytes = crc_util::calculate_from_bytes(crc_mode, expected_crc_bytes)?;
        crc_util::compare_crc(&crc_hex, calculated_crc_bytes)?;

        // 4. 创建 Rawfield (注意：是 *原始* 字节 `raw_bytes`)
        let raw_field = Rawfield::new(crc_bytes, "crc".into(), crc_hex);
        self.current_field = Some(raw_field.clone());
        self.fields.push(raw_field);

        // 5. 移动游标(crc通常在尾巴，是从后往前读，因此sop往前走)
        self.sop -= len;

        // 6. 返回 &mut self
        Ok(self)
    }

    // 根据起始脚标和终止脚标读取字节，不移动sop和pos . end_index可以为负值，此时从后往前数
    pub fn read_by_index_not_move(
        &self,
        start_index: usize,
        end_index: isize,
    ) -> ProtocolResult<&[u8]> {
        // 1. 解析 end_index
        let ei = if end_index >= 0 {
            // end_index 是正数，直接使用
            end_index as usize
        } else {
            // end_index 是负数，从 total 倒数
            // 使用 checked_add_signed 来安全地处理负数，防止下溢
            match (self.total as isize).checked_add(end_index) {
                Some(index) => {
                    if index < 0 {
                        // e.g. total=50, end_index=-60 -> -10
                        return Err(ProtocolError::ValidationFailed(format!(
                            "end_index {} is out of bounds",
                            end_index
                        )));
                    }
                    index as usize
                }
                None => {
                    // 几乎不可能发生，但在isize::MAX上可能
                    return Err(ProtocolError::ValidationFailed("end_index overflow".into()));
                }
            }
        };

        // 2. 边界安全检查
        if ei > self.total {
            return Err(ProtocolError::ValidationFailed(format!(
                "end_index {} (resolved to {}) is out of bounds ({})",
                end_index, ei, self.total
            )));
        }

        if start_index > ei {
            return Err(ProtocolError::ValidationFailed(format!(
                "start_index {} is greater than end_index {}",
                start_index, ei
            )));
        }

        // 3. 安全地返回切片 (零拷贝)
        // 此时100%确定 start_index <= ei <= self.total
        Ok(&self.buffer[start_index..ei])
    }

    pub fn check_crc<F>(
        &mut self,
        start_index: usize,         // 要计算的crc起始脚标
        end_index: isize,           // 要计算的crc结束脚标
        crc_pos_start_index: usize, // 报文里crc标段的起始脚标
        crc_pos_end_index: isize,   // 报文里crc标段的结束脚标
        checker: F,                 // 检查crc的方法
    ) -> ProtocolResult<&mut Self>
    where
        F: FnOnce(&[u8], &[u8]) -> ProtocolResult<()>,
    {
        let expected_calc_crc_fields = self.read_by_index_not_move(start_index, end_index);
        let crc_bytes = self.read_by_index_not_move(crc_pos_start_index, crc_pos_end_index);
        checker(expected_calc_crc_fields?, crc_bytes?)?;
        Ok(self)
    }
}
