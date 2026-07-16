//! # Memory transport settings
//!
//! 对应 Go `transport/internet/memory_settings.go`。

#[derive(Debug, Clone, Default)]
pub struct MemorySettings {
    pub read_buffer_size: usize,
    pub write_buffer_size: usize,
}

impl MemorySettings {
    #[must_use]
    pub fn default_8k() -> Self {
        Self { read_buffer_size: 8 * 1024, write_buffer_size: 8 * 1024 }
    }
    #[must_use]
    pub fn effective_read_size(&self) -> usize {
        if self.read_buffer_size == 0 { 8 * 1024 } else { self.read_buffer_size }
    }
    #[must_use]
    pub fn effective_write_size(&self) -> usize {
        if self.write_buffer_size == 0 { 8 * 1024 } else { self.write_buffer_size }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_uses_8k() {
        let s = MemorySettings::default();
        assert_eq!(s.effective_read_size(), 8 * 1024);
    }
}
