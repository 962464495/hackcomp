use std::io;
use std::num::ParseIntError;
use thiserror::Error;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("general io error")]
    IO(#[from] std::io::Error),

    #[error("maps parse error")]
    MapsParseError(#[from] MapsParseError),

    #[error("seccompiler")]
    Seccompiler(#[from] seccompiler::Error),

    #[error("seccompiler")]
    SeccompilerBackend(#[from] seccompiler::BackendError),

    #[error("unsupported architecture")]
    UnsupportedArch,

    #[error("Unknown error")]
    Unknown,
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
