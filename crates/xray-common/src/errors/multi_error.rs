//! 多错误聚合，对应 Go `common/errors/multi_error.go`。

use std::fmt;

use super::Error;

/// 聚合错误。
///
/// Display 格式对齐 Go：`multierr: {e} | {e} | `（每个错误后跟 ` | `，含末尾）。
#[derive(Debug)]
pub struct MultiError {
    errors: Vec<Error>,
}

impl fmt::Display for MultiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("multierr: ")?;
        for err in &self.errors {
            write!(f, "{} | ", err)?;
        }
        Ok(())
    }
}

impl std::error::Error for MultiError {}

/// 聚合多个可选错误，过滤 `None`；全部为 `None` 时返回 `None`。
///
/// 对应 Go `errors.Combine(maybeError ...error) error` 的 nil 过滤语义。
pub fn combine(errors: impl IntoIterator<Item = Option<Error>>) -> Option<MultiError> {
    let errs: Vec<Error> = errors.into_iter().flatten().collect();
    if errs.is_empty() {
        None
    } else {
        Some(MultiError { errors: errs })
    }
}

/// 检查 `actual`（或其每个聚合元素）是否都匹配 `expected`。
///
/// 对应 Go `errors.AllEqual`。Go 用 `errors.Is` 做哨兵比较；[`Error`] 无标识
/// 比较，以 Display 相等沿 `source()` 链近似（哨兵错误通常无包装）。
pub fn all_equal(expected: &Error, actual: &(dyn std::error::Error + 'static)) -> bool {
    if let Some(multi) = actual.downcast_ref::<MultiError>() {
        if multi.errors.is_empty() {
            return false;
        }
        multi.errors.iter().all(|e| chain_matches(e, expected))
    } else {
        chain_matches(actual, expected)
    }
}

/// `expected` 的 Display 是否出现在 `actual` 的 `source()` 链上。
fn chain_matches(actual: &(dyn std::error::Error + 'static), expected: &Error) -> bool {
    let mut err = actual;
    loop {
        if err.to_string() == expected.to_string() {
            return true;
        }
        match err.source() {
            Some(source) => err = source,
            None => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combine_all_none_is_none() {
        assert!(combine([None::<Error>, None]).is_none());
    }

    #[test]
    fn combine_filters_none() {
        let combined = combine([None, Some(Error::new("a")), None, Some(Error::new("b"))])
            .expect("non-empty");
        assert_eq!(combined.to_string(), "multierr: a | b | ");
    }

    #[test]
    fn combine_single_error_keeps_prefix() {
        let combined = combine([Some(Error::new("only"))].into_iter()).expect("non-empty");
        assert_eq!(combined.to_string(), "multierr: only | ");
    }

    #[test]
    fn combine_is_std_error() {
        let combined = combine([Some(Error::new("x"))].into_iter()).unwrap();
        let dyn_err: &(dyn std::error::Error + 'static) = &combined;
        assert_eq!(dyn_err.to_string(), "multierr: x | ");
    }

    #[test]
    fn all_equal_plain_match() {
        let expected = Error::new("EOF");
        assert!(all_equal(&expected, &Error::new("EOF")));
    }

    #[test]
    fn all_equal_plain_mismatch() {
        let expected = Error::new("EOF");
        assert!(!all_equal(&expected, &Error::new("other")));
    }

    #[test]
    fn all_equal_matches_inner_of_chain() {
        // Go errors.Is 沿 Unwrap 链比较；此处沿 source() 链。
        let expected = Error::new("root");
        let actual = Error::new("outer").with_inner(Error::new("root"));
        assert!(all_equal(&expected, &actual));
    }

    #[test]
    fn all_equal_multi_all_match() {
        let expected = Error::new("EOF");
        let multi = combine([Some(Error::new("EOF")), Some(Error::new("EOF"))]).unwrap();
        assert!(all_equal(&expected, &multi));
    }

    #[test]
    fn all_equal_multi_one_mismatch() {
        let expected = Error::new("EOF");
        let multi = combine([Some(Error::new("EOF")), Some(Error::new("boom"))]).unwrap();
        assert!(!all_equal(&expected, &multi));
    }
}
