//! Version variables and its utils

/// Major version
pub const MAJOR: u32 = 0;
/// Minor version
pub const MINOR: u32 = 2;
/// Patch version
pub const PATCH: u32 = 1;

/// Export versions as string
pub fn as_string() -> String {
    format!("{}.{}.{}", MAJOR, MINOR, PATCH)
}

#[cfg(test)]
mod tests {
    use crate::version;

    #[test]
    fn test_version_string() {
        let expected = "0.2.1";

        assert_eq!(version::MAJOR, 0, "wrong version");
        assert_eq!(version::MINOR, 2, "wrong version");
        assert_eq!(version::PATCH, 1, "wrong version");
        assert_eq!(version::as_string(), expected, "wrong version");
    }
}
