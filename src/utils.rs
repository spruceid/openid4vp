use anyhow::{bail, Error};
use serde::{Deserialize, Serialize};
use std::ops::Deref;

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(try_from = "Vec<T>")]
pub struct NonEmptyVec<T>(Vec<T>);

impl<T> NonEmptyVec<T> {
    pub fn new(t: T) -> Self {
        Self(vec![t])
    }

    pub fn maybe_new(v: Vec<T>) -> Option<Self> {
        Self::try_from(v).ok()
    }

    pub fn push(&mut self, t: T) {
        self.0.push(t)
    }

    pub fn into_inner(self) -> Vec<T> {
        self.0
    }
}

impl<T> TryFrom<Vec<T>> for NonEmptyVec<T> {
    type Error = Error;

    fn try_from(v: Vec<T>) -> Result<NonEmptyVec<T>, Error> {
        if v.is_empty() {
            bail!("cannot create a NonEmptyVec from an empty Vec")
        }
        Ok(NonEmptyVec(v))
    }
}

impl<T> From<NonEmptyVec<T>> for Vec<T> {
    fn from(NonEmptyVec(v): NonEmptyVec<T>) -> Vec<T> {
        v
    }
}

impl<T> AsRef<[T]> for NonEmptyVec<T> {
    fn as_ref(&self) -> &[T] {
        &self.0
    }
}

impl<T> Deref for NonEmptyVec<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.0
    }
}

impl<'a, T> IntoIterator for &'a NonEmptyVec<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T> IntoIterator for NonEmptyVec<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T: Serialize> Serialize for NonEmptyVec<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}
