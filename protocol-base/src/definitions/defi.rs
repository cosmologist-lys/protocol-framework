pub enum CrcType {
    Crc16Ccitt,
    Crc16CcittFalse,
    Crc16Modbus,
    Crc16Xmodem,
    /// 可自定义参数的 CCITT-16 算法
    Crc16CcittCustom {
        poly: u16,
        init: u16,
        xor_out: u16,
        swap_result: bool,
    },
}
