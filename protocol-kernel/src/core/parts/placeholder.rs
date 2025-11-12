// 占位符
#[derive(Debug, Clone, Default)]
pub struct PlaceHolder {
    pub(crate) tag: String,
    pub(crate) pos: usize,
    pub(crate) start_index: usize,
    pub(crate) end_index: usize,
}

impl PlaceHolder {
    pub fn new(tag: &str, pos: usize, start_index: usize, end_index: usize) -> Self {
        Self {
            tag: tag.into(),
            pos,
            start_index,
            end_index,
        }
    }

    /// 获取占位符的长度
    pub fn capacity(&self) -> usize {
        self.end_index - self.start_index
    }

    // Getter methods
    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub fn tag_clone(&self) -> String {
        self.tag.clone()
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn start_index(&self) -> usize {
        self.start_index
    }

    pub fn end_index(&self) -> usize {
        self.end_index
    }
}
