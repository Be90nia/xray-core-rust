//! OCSP（在线证书状态协议）支持
//!
//! 对应 Go 版本 `common/ocsp` 包。
//! 当前为占位实现，完整的 OCSP 需要证书解析功能，将在后续阶段完成。

use std::path::Path;

/// OCSP 响应状态码
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspStatus {
    /// 证书状态良好
    Good,
    /// 证书已吊销
    Revoked,
    /// 证书状态未知
    Unknown,
}

impl OcspStatus {
    /// 从数值代码创建 OcspStatus。
    ///
    /// 对应 OCSP 响应中的 status 字段：
    /// - 0: Good
    /// - 1: Revoked
    /// - 2: Unknown
    pub fn from_code(code: i32) -> Self {
        match code {
            0 => OcspStatus::Good,
            1 => OcspStatus::Revoked,
            _ => OcspStatus::Unknown,
        }
    }

    /// 转换为数值代码。
    pub fn to_code(self) -> i32 {
        match self {
            OcspStatus::Good => 0,
            OcspStatus::Revoked => 1,
            OcspStatus::Unknown => 2,
        }
    }
}

/// OCSP 响应数据
#[derive(Debug, Clone)]
pub struct OcspResponse {
    /// 证书状态
    pub status: OcspStatus,
    /// 此更新时间
    pub this_update: Option<std::time::SystemTime>,
    /// 下次更新时间
    pub next_update: Option<std::time::SystemTime>,
    /// 吊销时间（仅 Revoked 状态有效）
    pub revocation_time: Option<std::time::SystemTime>,
    /// 吊销原因代码
    pub revocation_reason: Option<u8>,
}

impl OcspResponse {
    /// 创建 Good 状态的 OCSP 响应。
    pub fn good() -> Self {
        Self {
            status: OcspStatus::Good,
            this_update: None,
            next_update: None,
            revocation_time: None,
            revocation_reason: None,
        }
    }

    /// 创建 Revoked 状态的 OCSP 响应。
    pub fn revoked(revocation_time: std::time::SystemTime, reason: u8) -> Self {
        Self {
            status: OcspStatus::Revoked,
            this_update: None,
            next_update: None,
            revocation_time: Some(revocation_time),
            revocation_reason: Some(reason),
        }
    }

    /// 创建 Unknown 状态的 OCSP 响应。
    pub fn unknown() -> Self {
        Self {
            status: OcspStatus::Unknown,
            this_update: None,
            next_update: None,
            revocation_time: None,
            revocation_reason: None,
        }
    }

    /// 检查证书是否状态良好。
    pub fn is_good(&self) -> bool {
        self.status == OcspStatus::Good
    }

    /// 检查证书是否已吊销。
    pub fn is_revoked(&self) -> bool {
        self.status == OcspStatus::Revoked
    }
}

/// OCSP 错误类型
#[derive(Debug, thiserror::Error)]
pub enum OcspError {
    /// 证书解析失败
    #[error("certificate parsing failed: {0}")]
    ParseError(String),
    /// OCSP 请求失败
    #[error("OCSP request failed: {0}")]
    RequestFailed(String),
    /// 无效的 OCSP 响应
    #[error("invalid OCSP response: {0}")]
    InvalidResponse(String),
    /// 功能不支持
    #[error("not supported: {0}")]
    NotSupported(String),
}

/// 从 DER 编码的证书文件获取 OCSP 响应。
///
/// 对应 Go 版本 `ocsp.GetOCSPForFile`。
///
/// # 注意
/// 当前为占位实现，完整 OCSP 需要证书解析功能。
pub fn get_ocsp_for_file(_path: &Path) -> Result<Option<OcspResponse>, OcspError> {
    Err(OcspError::NotSupported(
        "OCSP certificate parsing is not yet implemented".into(),
    ))
}

/// 从证书字节获取 OCSP stapling 响应。
///
/// 对应 Go 版本 `ocsp.GetOCSPStapling`。
///
/// # 注意
/// 当前为占位实现。
pub fn get_ocsp_stapling(_cert_der: &[u8]) -> Result<Option<OcspResponse>, OcspError> {
    Err(OcspError::NotSupported(
        "OCSP stapling is not yet implemented".into(),
    ))
}

/// 从证书 DER 字节获取 OCSP 响应。
///
/// 对应 Go 版本 `ocsp.GetOCSPForCert`。
///
/// # 注意
/// 当前为占位实现。
pub fn get_ocsp_for_cert(_cert_der: &[u8]) -> Result<Option<OcspResponse>, OcspError> {
    Err(OcspError::NotSupported(
        "OCSP for certificate is not yet implemented".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ocsp_status_from_code() {
        assert_eq!(OcspStatus::from_code(0), OcspStatus::Good);
        assert_eq!(OcspStatus::from_code(1), OcspStatus::Revoked);
        assert_eq!(OcspStatus::from_code(2), OcspStatus::Unknown);
        assert_eq!(OcspStatus::from_code(-1), OcspStatus::Unknown);
        assert_eq!(OcspStatus::from_code(99), OcspStatus::Unknown);
    }

    #[test]
    fn test_ocsp_status_to_code() {
        assert_eq!(OcspStatus::Good.to_code(), 0);
        assert_eq!(OcspStatus::Revoked.to_code(), 1);
        assert_eq!(OcspStatus::Unknown.to_code(), 2);
    }

    #[test]
    fn test_ocsp_status_roundtrip() {
        for code in 0..3 {
            assert_eq!(OcspStatus::from_code(code).to_code(), code);
        }
    }

    #[test]
    fn test_ocsp_response_good() {
        let resp = OcspResponse::good();
        assert!(resp.is_good());
        assert!(!resp.is_revoked());
        assert_eq!(resp.status, OcspStatus::Good);
        assert!(resp.revocation_time.is_none());
        assert!(resp.revocation_reason.is_none());
    }

    #[test]
    fn test_ocsp_response_revoked() {
        let now = std::time::SystemTime::now();
        let resp = OcspResponse::revoked(now, 1);
        assert!(!resp.is_good());
        assert!(resp.is_revoked());
        assert_eq!(resp.status, OcspStatus::Revoked);
        assert!(resp.revocation_time.is_some());
        assert_eq!(resp.revocation_reason, Some(1));
    }

    #[test]
    fn test_ocsp_response_unknown() {
        let resp = OcspResponse::unknown();
        assert!(!resp.is_good());
        assert!(!resp.is_revoked());
        assert_eq!(resp.status, OcspStatus::Unknown);
    }

    #[test]
    fn test_get_ocsp_for_file_not_supported() {
        let result = get_ocsp_for_file(Path::new("/tmp/test.crt"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OcspError::NotSupported(_)));
    }

    #[test]
    fn test_get_ocsp_stapling_not_supported() {
        let result = get_ocsp_stapling(&[]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OcspError::NotSupported(_)));
    }

    #[test]
    fn test_get_ocsp_for_cert_not_supported() {
        let result = get_ocsp_for_cert(&[]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OcspError::NotSupported(_)));
    }

    #[test]
    fn test_ocsp_error_display() {
        let err = OcspError::ParseError("test".into());
        assert!(err.to_string().contains("test"));

        let err = OcspError::RequestFailed("timeout".into());
        assert!(err.to_string().contains("timeout"));

        let err = OcspError::InvalidResponse("bad".into());
        assert!(err.to_string().contains("bad"));

        let err = OcspError::NotSupported("stub".into());
        assert!(err.to_string().contains("stub"));
    }
}
