use std::num::ParseIntError;
use thiserror::Error;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("general io error")]
    IO(#[from] std::io::Error),

    #[error("syscall error: {0}")]
    Syscall(nc::Errno),

    #[error("maps parse error")]
    MapsParseError(#[from] MapsParseError),

    #[error("seccompiler")]
    Seccompiler(#[from] seccompiler::Error),

    #[error("seccompiler")]
    SeccompilerBackend(#[from] seccompiler::BackendError),

    #[error("unsupported architecture")]
    UnsupportedArch,

    #[error("already installed")]
    AlreadyInstalled,

    #[error("Unknown error")]
    Unknown,
}

impl From<nc::Errno> for Error {
    fn from(value: nc::Errno) -> Self {
        Error::Syscall(value)
    }
}

#[derive(Error, Debug)]
pub enum MapsParseError {
    #[error("Maps file contains invalid UTF-8 data")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("Line is malformed: '{line}'")]
    MalformedLine { line: String },

    #[error("Failed to parse component '{component}'")]
    ParseComponent {
        component: String,
        #[source]
        source: ParseIntError,
    },
}

pub type Result<T, E = Error> = core::result::Result<T, E>;
