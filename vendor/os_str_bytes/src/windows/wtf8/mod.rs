// This module implements the WTF-8 encoding specification:
// https://simonsapin.github.io/wtf-8/

use super::EncodingError;
use super::Result;

mod code_points;
use code_points::CodePoints;

mod convert;
pub(super) use convert::encode_wide;
pub(super) use convert::DecodeWide;

if_raw! {
    mod string;
    pub(super) use string::ends_with;
    pub(super) use string::starts_with;
}

const BYTE_SHIFT: u8 = 6;

const CONT_MASK: u8 = (1 << BYTE_SHIFT) - 1;

const CONT_TAG: u8 = 0b1000_0000;

const fn is_continuation(byte: u8) -> bool {
    byte & !CONT_MASK == CONT_TAG
}
