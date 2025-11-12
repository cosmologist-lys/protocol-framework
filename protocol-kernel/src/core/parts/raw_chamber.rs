use crate::core::parts::raw_capsule::RawCapsule;
use crate::core::parts::traits::Cmd;

/// 对上行而言，它通常需要回复。因此上行需要2个raw-capsule，一上一下. RawChamber用来组合2个raw-capsule
/// 对下行而言，它只需要一个下行的raw-capsule. 此时不需要RawChamber

#[derive(Debug, Clone, Default)]
pub struct RawChamber<T: Cmd + Clone> {
    pub(crate) upstream: Option<RawCapsule<T>>,
    pub(crate) downstream: Option<RawCapsule<T>>,
    pub(crate) cmd_code: String,
    pub(crate) success: bool,
}

impl<T: Cmd + Clone> RawChamber<T> {
    pub fn new(in_capsule: &RawCapsule<T>, out_capsule: &RawCapsule<T>) -> Self {
        // 优先从 out_capsule 获取 cmd_code
        let cmd_code = out_capsule
            .cmd
            .as_ref()
            .map(|cmd| cmd.code())
            .or_else(|| in_capsule.cmd.as_ref().map(|cmd| cmd.code()))
            .unwrap_or_default();

        // 两个 capsule 的 success 都是 true 时，self.success 才为 true
        let success = in_capsule.success && out_capsule.success;

        Self {
            upstream: Some(in_capsule.clone()),
            downstream: Some(out_capsule.clone()),
            cmd_code,
            success,
        }
    }

    // Getter methods
    pub fn upstream(&self) -> Option<&RawCapsule<T>> {
        self.upstream.as_ref()
    }

    pub fn upstream_clone(&self) -> Option<RawCapsule<T>> {
        self.upstream.clone()
    }

    pub fn downstream(&self) -> Option<&RawCapsule<T>> {
        self.downstream.as_ref()
    }

    pub fn downstream_clone(&self) -> Option<RawCapsule<T>> {
        self.downstream.clone()
    }

    pub fn cmd_code(&self) -> &str {
        &self.cmd_code
    }

    pub fn cmd_code_clone(&self) -> String {
        self.cmd_code.clone()
    }

    pub fn success(&self) -> bool {
        self.success
    }

    pub fn device_no(&self) -> Option<&str>
    where
        T: 'static,
    {
        self.upstream
            .as_ref()
            .and_then(|cap| cap.device_no())
            .or_else(|| self.downstream.as_ref().and_then(|cap| cap.device_no()))
    }

    pub fn device_no_clone(&self) -> Option<String>
    where
        T: 'static,
    {
        self.upstream
            .as_ref()
            .and_then(|cap| cap.device_no_clone())
            .or_else(|| {
                self.downstream
                    .as_ref()
                    .and_then(|cap| cap.device_no_clone())
            })
    }

    pub fn device_id(&self) -> Option<&str>
    where
        T: 'static,
    {
        self.upstream
            .as_ref()
            .and_then(|cap| cap.device_id())
            .or_else(|| self.downstream.as_ref().and_then(|cap| cap.device_id()))
    }

    pub fn device_id_clone(&self) -> Option<String>
    where
        T: 'static,
    {
        self.upstream
            .as_ref()
            .and_then(|cap| cap.device_id_clone())
            .or_else(|| {
                self.downstream
                    .as_ref()
                    .and_then(|cap| cap.device_id_clone())
            })
    }
}
