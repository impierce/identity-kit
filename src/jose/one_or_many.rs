//! `OneOrMany`, the one-value-or-a-list shape of JSON members such as `aud`.

use serde::{Deserialize, Serialize};

/// A value that is either one `T` or a list of them, serialized without the list when single.
///
/// RFC 7519 uses this for `aud`; DID Core for `controller` and the `type` of a service.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    /// A single value.
    One(T),
    /// A list of values, kept as a list even when it holds one.
    Many(Vec<T>),
}

impl<T> OneOrMany<T> {
    /// The values, in order.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        match self {
            Self::One(one) => core::slice::from_ref(one).iter(),
            Self::Many(many) => many.iter(),
        }
    }

    /// The values, mutably.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        match self {
            Self::One(one) => core::slice::from_mut(one).iter_mut(),
            Self::Many(many) => many.iter_mut(),
        }
    }

    /// The number of values.
    pub fn len(&self) -> usize {
        match self {
            Self::One(_) => 1,
            Self::Many(many) => many.len(),
        }
    }

    /// Whether there are no values (an empty list).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The first value, if any.
    pub fn first(&self) -> Option<&T> {
        self.iter().next()
    }

    /// Whether `value` is among the values.
    pub fn contains(&self, value: &T) -> bool
    where
        T: PartialEq,
    {
        self.iter().any(|v| v == value)
    }

    /// The values as a `Vec`.
    pub fn into_vec(self) -> Vec<T> {
        match self {
            Self::One(one) => vec![one],
            Self::Many(many) => many,
        }
    }
}

impl<T> From<T> for OneOrMany<T> {
    fn from(value: T) -> Self {
        Self::One(value)
    }
}

impl<T> From<Vec<T>> for OneOrMany<T> {
    fn from(values: Vec<T>) -> Self {
        Self::Many(values)
    }
}

impl From<&str> for OneOrMany<String> {
    fn from(value: &str) -> Self {
        Self::One(value.to_owned())
    }
}
