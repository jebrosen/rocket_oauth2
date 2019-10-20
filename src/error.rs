use std::error::Error as StdError;
use std::fmt::{self, Display};

/// Represents any kind of error that can occur during authorization.
/// Most of these errors are returned by an [`Adapter`](super::Adapter).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// An error occurred during URI parsing or construction. This usually means
    /// the token exchange endpoint is incorrect. The attempted URI is included.
    InvalidUri(String),
    /// A token exchange request failed, for example because the server could
    /// not be reached, or the response body could not be parsed.
    ExchangeFailure,
    /// A token exchange request errored (the response code indicated failure).
    /// The response code is included.
    ExchangeError(u16),
    /// Another kind of error occurred.
    Other,
}

/// Represents an error during authorization. [`Error`] has a
/// [`kind`](Error::kind) and a [`source`](std::error::Error::source)
/// which describe the error.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    source: Option<Box<dyn StdError + Send + Sync>>,
}

impl Error {
    /// Create a new `Error` with no source.
    pub fn new(kind: ErrorKind) -> Self {
        Self { kind, source: None }
    }

    /// Create a new `Error` given a `kind` and `source`.
    pub fn new_from<E>(kind: ErrorKind, source: E) -> Self
    where
        E: Into<Box<dyn StdError + Send + Sync>>,
    {
        Self {
            kind,
            source: Some(source.into()),
        }
    }

    /// Returns the kind of error that occurred.
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.kind {
            ErrorKind::InvalidUri(uri) => write!(f, "invalid URI: '{}'", uri)?,
            ErrorKind::ExchangeFailure => write!(f, "failed to exchange token")?,
            ErrorKind::ExchangeError(code) => write!(
                f,
                "token exchange returned non-success status code: {}",
                code
            )?,
            ErrorKind::Other => write!(f, "an unknown error occurred")?,
        }

        if let Some(error) = &self.source {
            write!(f, ": {}", error)?;
        }

        Ok(())
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source.as_ref().map(|e| &**e as _)
    }
}
