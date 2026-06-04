//! Extension and environment traits for optional features.
//!
//! Corresponds to Go's `features/extension` package.

use async_trait::async_trait;

/// Feature type identifier for Extension.
pub const FEATURE_EXTENSION: &str = "extension";

/// Extension trait for optional features.
///
/// Corresponds to Go's `features/extension.Extension`.
#[async_trait]
pub trait Extension: Send + Sync {
    /// Get the extension type name.
    fn type_name(&self) -> &str;
}

/// Environment interface for accessing configuration.
///
/// Corresponds to Go's `features/extension.Environment`.
#[async_trait]
pub trait Environment: Send + Sync {
    /// Get a configuration value by key.
    fn get_config(&self, key: &str) -> Option<String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_extension_constant() {
        assert_eq!(FEATURE_EXTENSION, "extension");
    }

    /// Mock extension for testing.
    struct MockExtension {
        name: String,
    }

    impl MockExtension {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
            }
        }
    }

    #[async_trait]
    impl Extension for MockExtension {
        fn type_name(&self) -> &str {
            &self.name
        }
    }

    #[test]
    fn test_mock_extension() {
        let ext = MockExtension::new("observatory");
        assert_eq!(ext.type_name(), "observatory");
    }

    /// Mock environment for testing.
    struct MockEnvironment {
        config: std::collections::HashMap<String, String>,
    }

    impl MockEnvironment {
        fn new() -> Self {
            Self {
                config: std::collections::HashMap::new(),
            }
        }
    }

    #[async_trait]
    impl Environment for MockEnvironment {
        fn get_config(&self, key: &str) -> Option<String> {
            self.config.get(key).cloned()
        }
    }

    #[test]
    fn test_mock_environment_missing_key() {
        let env = MockEnvironment::new();
        assert!(env.get_config("missing").is_none());
    }

    #[test]
    fn test_extension_trait_object_safe() {
        let ext: Box<dyn Extension> = Box::new(MockExtension::new("test"));
        assert_eq!(ext.type_name(), "test");
    }

    #[test]
    fn test_environment_trait_object_safe() {
        let env: Box<dyn Environment> = Box::new(MockEnvironment::new());
        assert!(env.get_config("key").is_none());
    }
}
