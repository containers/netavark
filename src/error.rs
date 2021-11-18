use std::error::Error;
use std::fmt;

#[derive(Serialize, Deserialize, Debug)]
pub struct NetavarkError {
    pub error: String,
    // Do not serialize this field we already get the exit code when the program exits so there is no need to include it.
    #[serde(skip_serializing)]
    pub errno: i32,
}

impl fmt::Display for NetavarkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(&self).unwrap())
    }
}

impl Error for NetavarkError {}
