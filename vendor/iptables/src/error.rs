use std::convert::From;
use std::error::Error;
use std::fmt;
use std::process::Output;

#[derive(Debug)]
pub struct IptablesError {
    pub code: i32,
    pub msg: String,
}

impl fmt::Display for IptablesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "code: {}, msg: {}", self.code, self.msg)
    }
}

impl From<Output> for IptablesError {
    fn from(output: Output) -> Self {
        Self {
            code: output.status.code().unwrap_or(-1),
            msg: String::from_utf8_lossy(output.stderr.as_slice()).into(),
        }
    }
}

impl Error for IptablesError {}
