//! 错误收集器：累积底层连接错误，生成报告。
//!
//! 对应 Go `app/observatory/explainErrors.go` 的 `errorCollector`。

use parking_lot::Mutex;

use crate::error::ObservatoryError;

/// 错误收集器：累积多个底层错误，最终输出一个串联的错误。
pub struct ErrorCollector {
    errors: Mutex<Vec<String>>,
}

impl ErrorCollector {
    pub fn new() -> Self {
        Self {
            errors: Mutex::new(Vec::new()),
        }
    }

    /// 提交一个错误（仅记录字符串描述，避免泛化错误类型）。
    pub fn submit(&self, err_description: impl Into<String>) {
        self.errors.lock().push(err_description.into());
    }

    /// 是否已收集到任何错误。
    pub fn has_errors(&self) -> bool {
        !self.errors.lock().is_empty()
    }

    /// 已收集的错误数。
    pub fn count(&self) -> usize {
        self.errors.lock().len()
    }

    /// 生成最终报告：若无错误，返回 FailedToProduceReport；否则串联为 UnderlyingConnectionError。
    ///
    /// 对应 Go `UnderlyingError()`。
    pub fn underlying_error(&self) -> ObservatoryError {
        let g = self.errors.lock();
        if g.is_empty() {
            return ObservatoryError::FailedToProduceReport;
        }
        ObservatoryError::UnderlyingConnectionError(g.join("; "))
    }
}

impl Default for ErrorCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_collector_is_empty() {
        let c = ErrorCollector::new();
        assert!(!c.has_errors());
        assert_eq!(c.count(), 0);
    }

    #[test]
    fn submit_increments_count() {
        let c = ErrorCollector::new();
        c.submit("err1");
        c.submit("err2");
        assert_eq!(c.count(), 2);
        assert!(c.has_errors());
    }

    #[test]
    fn underlying_error_empty_returns_failed_to_produce() {
        let c = ErrorCollector::new();
        let err = c.underlying_error();
        assert!(matches!(err, ObservatoryError::FailedToProduceReport));
    }

    #[test]
    fn underlying_error_single_returns_underlying() {
        let c = ErrorCollector::new();
        c.submit("connection refused");
        let err = c.underlying_error();
        match err {
            ObservatoryError::UnderlyingConnectionError(msg) => {
                assert!(msg.contains("connection refused"));
            }
            _ => panic!("expected UnderlyingConnectionError"),
        }
    }

    #[test]
    fn underlying_error_multiple_joined_with_semicolon() {
        let c = ErrorCollector::new();
        c.submit("err1");
        c.submit("err2");
        c.submit("err3");
        let err = c.underlying_error();
        match err {
            ObservatoryError::UnderlyingConnectionError(msg) => {
                assert!(msg.contains("err1"));
                assert!(msg.contains("err2"));
                assert!(msg.contains("err3"));
                assert!(msg.contains(";"));
            }
            _ => panic!("expected UnderlyingConnectionError"),
        }
    }

    #[test]
    fn default_is_empty() {
        let c = ErrorCollector::default();
        assert!(!c.has_errors());
    }

    #[test]
    fn thread_safe_concurrent_submit() {
        use std::sync::Arc;
        use std::thread;

        let c = Arc::new(ErrorCollector::new());
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let c = c.clone();
                thread::spawn(move || {
                    c.submit(format!("err{i}"));
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(c.count(), 8);
    }
}
