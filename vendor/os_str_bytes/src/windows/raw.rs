use super::wtf8;

pub(crate) fn ends_with(string: &[u8], suffix: &[u8]) -> bool {
    wtf8::ends_with(string, suffix).unwrap_or(false)
}

pub(crate) fn starts_with(string: &[u8], prefix: &[u8]) -> bool {
    wtf8::starts_with(string, prefix).unwrap_or(false)
}
