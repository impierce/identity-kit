//! The source of an error, shown after its message.

use core::fmt;

/// `": {source}"` when there is a source, nothing otherwise: for an error whose message names
/// what went wrong and whose source, when it has one, says why.
pub(crate) struct Cause<'a, T: ?Sized>(Option<&'a T>);

impl<T: fmt::Display + ?Sized> fmt::Display for Cause<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(source) => write!(f, ": {source}"),
            None => Ok(()),
        }
    }
}

/// The [`Cause`] of `source`.
pub(crate) fn cause<T: ?Sized>(source: Option<&T>) -> Cause<'_, T> {
    Cause(source)
}
