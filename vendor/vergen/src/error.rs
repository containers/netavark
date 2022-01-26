// Copyright (c) 2016, 2018, 2021 vergen developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! `vergen` errors

use std::fmt;

enum ErrKind {
    Protocol,
    Env,
}

impl fmt::Display for ErrKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let err_kind = match self {
            Self::Protocol => "protocol",
            Self::Env => "env",
        };
        write!(f, "{}", err_kind)
    }
}

/// An error generated from the `vergen` library
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    /// An error from the `git2` library
    #[cfg(feature = "git")]
    #[error("{}: An error occurred in the 'git2' library: {}", ErrKind::Protocol, .0)]
    Git2(#[from] git2::Error),
    /// An error writing the cargo instructions to stdout
    #[error("{}: There was an error writing the cargo instructions to stdout: {}", ErrKind::Protocol, .0)]
    Io(#[from] std::io::Error),
    /// An error from the `rustc_version` library
    #[error("{}: An error occurred in the 'rustc_version' library: {}", ErrKind::Protocol, .0)]
    #[cfg(feature = "rustc")]
    RustcVersion(#[from] rustc_version::Error),
    /// An error getting the 'CARGO_PKG_VERSION' environment variable
    #[error("{}: The 'CARGO_PKG_VERSION' environment variable may not be set: {}", ErrKind::Env, .0)]
    Var(#[from] std::env::VarError),
    /// An error getting the current pid
    #[cfg(feature = "si")]
    #[error(
        "{}: Unable to determine the current process pid: {}",
        ErrKind::Protocol,
        msg
    )]
    #[cfg(not(target_os = "macos"))]
    Pid { msg: &'static str },
}

#[cfg(test)]
mod test {
    use super::Error;
    #[cfg(feature = "git")]
    use git2::Repository;
    #[cfg(feature = "rustc")]
    use rustc_version::version_meta_for;
    use std::{
        env,
        io::{self, ErrorKind},
    };

    #[test]
    fn io_error() {
        let err: Error = io::Error::new(ErrorKind::Other, "testing").into();
        assert_eq!(
            "protocol: There was an error writing the cargo instructions to stdout: testing",
            format!("{}", err)
        );
    }

    #[cfg(feature = "rustc")]
    #[test]
    fn rustc_version_error() {
        let res = version_meta_for("yoda").map_err(|e| Error::from(e));
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert_eq!(
            "protocol: An error occurred in the \'rustc_version\' library: unexpected `rustc -vV` format",
            format!("{}", err)
        );
    }

    #[cfg(feature = "git")]
    #[test]
    fn git2_error() {
        let res = Repository::open("blah").map_err(|e| Error::from(e));
        assert!(res.is_err());
        let err = res.err().unwrap();
        #[cfg(target_family = "unix")]
        assert_eq!("protocol: An error occurred in the \'git2\' library: failed to resolve path \'blah\': No such file or directory; class=Os (2); code=NotFound (-3)", format!("{}", err));
        #[cfg(target_family = "windows")]
        assert_eq!("protocol: An error occurred in the \'git2\' library: failed to resolve path \'blah\': The system cannot find the file specified.\r\n; class=Os (2); code=NotFound (-3)", format!("{}", err));
    }

    #[cfg(all(feature = "si", not(target_os = "macos")))]
    #[test]
    fn pid_error() {
        let err: Error = Error::Pid { msg: "test" };
        assert_eq!(
            "protocol: Unable to determine the current process pid: test",
            format!("{}", err)
        );
    }

    #[test]
    fn var_error() {
        let res = env::var("yoda").map_err(|e| Error::from(e));
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert_eq!(
            "env: The \'CARGO_PKG_VERSION\' environment variable may not be set: environment variable not found",
            format!("{}", err)
        );
    }
}
