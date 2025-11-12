use crate::{core::parts::traits::Cmd, DirectionEnum, ProtocolError, ReportField};
use dyn_clone::DynClone;

// 报文上/下行解析 处理之后的结果 第二小解析单位，比RawField大
#[derive(Debug, Clone)]
pub struct RawCapsule<T: Cmd> {
    pub(crate) bytes: Vec<u8>,
    pub(crate) hex: String,
    pub(crate) field_details: Vec<ReportField>,
    pub(crate) cmd: Option<T>,
    pub(crate) device_no: Option<String>,
    pub(crate) device_id: Option<String>,
    // 临时二进制存放处
    pub(crate) temp_bytes: Vec<u8>,
    pub(crate) direction: DirectionEnum,
    pub(crate) success: bool,
}

impl<T: Cmd + 'static> RawCapsule<T> {
    pub fn new_upstream(bytes: &[u8]) -> Self {
        let hex = hex::encode_upper(bytes);
        Self {
            bytes: bytes.to_vec(),
            hex,
            field_details: Vec::new(),
            cmd: None,
            device_no: None,
            device_id: None,
            temp_bytes: Vec::new(),
            direction: DirectionEnum::Upstream,
            success: true,
        }
    }

    pub fn new_downstream(cmd: T, device_no: &str, device_id: &str) -> Self {
        Self {
            bytes: Vec::new(),
            hex: String::new(),
            field_details: Vec::new(),
            cmd: Some(cmd),
            device_no: Some(device_no.into()),
            device_id: if device_id.is_empty() {
                None
            } else {
                Some(device_id.into())
            },
            temp_bytes: Vec::new(),
            direction: DirectionEnum::Downstream,
            success: true,
        }
    }

    // 获取一个唯一值。它由device_id和device_no一起组成
    pub fn get_unique_id(&self) -> protocol_base::ProtocolResult<String> {
        let device_no = if let Some(dn) = self.device_no.as_ref() {
            dn.clone()
        } else {
            "0".into()
        };

        let device_id = if let Some(dn) = self.device_id.as_ref() {
            dn.clone()
        } else {
            "0".into()
        };

        if device_no == "0" && device_id == "0" {
            return Err(ProtocolError::CommonError(
                "RawCapsule requires at least 1 of device_no and device_id but found both none"
                    .into(),
            ));
        }
        Ok("unique_".to_string() + &device_no + "_" + &device_id)
    }

    pub fn new_downstream_from_upstream(up_stream_capsule: &RawCapsule<T>) -> Self {
        let device_no = if up_stream_capsule.device_no.is_some() {
            up_stream_capsule.device_no.clone()
        } else {
            None
        };

        let device_id = if up_stream_capsule.device_id.is_some() {
            up_stream_capsule.device_id.clone()
        } else {
            None
        };
        Self {
            bytes: Vec::new(),
            hex: String::new(),
            field_details: Vec::new(),
            cmd: up_stream_capsule.cmd_clone(),
            device_no,
            device_id,
            temp_bytes: Vec::new(),
            direction: DirectionEnum::Downstream,
            success: true,
        }
    }

    pub fn into_fields(self) -> Vec<ReportField> {
        self.field_details
    }

    pub fn fail(&mut self) {
        self.success = false;
    }

    pub fn is_success(&self) -> bool {
        self.success
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn bytes_clone(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    pub fn hex(&self) -> &str {
        &self.hex
    }

    pub fn hex_clone(&self) -> String {
        self.hex.clone()
    }

    pub fn field_details(&self) -> &[ReportField] {
        &self.field_details
    }

    pub fn field_details_clone(&self) -> Vec<ReportField> {
        self.field_details.clone()
    }

    pub fn cmd(&self) -> Option<&T> {
        self.cmd.as_ref()
    }

    pub fn cmd_clone(&self) -> Option<T>
    where
        T: DynClone,
    {
        self.cmd.as_ref().map(|cmd| dyn_clone::clone(cmd))
    }

    pub fn device_no(&self) -> Option<&str> {
        self.device_no.as_deref()
    }

    pub fn device_no_clone(&self) -> Option<String> {
        self.device_no.clone()
    }

    pub fn device_id(&self) -> Option<&str> {
        self.device_id.as_deref()
    }

    pub fn device_id_clone(&self) -> Option<String> {
        self.device_id.clone()
    }

    pub fn temp_bytes(&self) -> &[u8] {
        &self.temp_bytes
    }

    pub fn temp_bytes_clone(&self) -> Vec<u8> {
        self.temp_bytes.clone()
    }

    pub fn direction(&self) -> &DirectionEnum {
        &self.direction
    }

    pub fn direction_clone(&self) -> DirectionEnum {
        self.direction.clone()
    }

    pub fn success(&self) -> bool {
        self.success
    }

    // 把二进制塞回去，同时自动生成hex,通常用于出口的capsule
    pub fn set_bytes_and_generate_hex(
        &mut self,
        bytes: &[u8],
    ) -> protocol_base::ProtocolResult<()> {
        self.bytes = bytes.to_vec();
        self.hex = crate::utils::hex_util::bytes_to_hex(bytes)?;
        Ok(())
    }

    pub fn is_upstream(&self) -> bool {
        self.direction.is_upstream()
    }

    pub fn is_downstream(&self) -> bool {
        self.direction.is_downstream()
    }

    pub fn set_device_id(&mut self, device_id: &str) {
        self.device_id = Some(device_id.into());
    }

    pub fn set_device_no(&mut self, device_no: &str) {
        self.device_no = Some(device_no.into());
    }

    pub fn set_cmd(&mut self, cmd: T) {
        self.cmd = Some(cmd);
    }

    pub fn set_temp_bytes(&mut self, bytes: &[u8]) {
        self.temp_bytes = bytes.to_vec();
    }

    pub fn set_fields(&mut self, fields: Vec<ReportField>) {
        self.field_details = fields;
    }

    pub fn append_fields(&mut self, fields: Vec<ReportField>) {
        self.field_details.extend(fields);
    }

    pub fn prepend_fields(&mut self, fields: Vec<ReportField>) {
        let mut new_fields = fields;
        new_fields.append(&mut self.field_details);
        self.field_details = new_fields;
    }
}
