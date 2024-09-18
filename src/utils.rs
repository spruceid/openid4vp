use anyhow::{bail, Error};
use serde::{Deserialize, Serialize};
use std::ops::Deref;

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(try_from = "Vec<T>", into = "Vec<T>")]
pub struct NonEmptyVec<T: Clone>(Vec<T>);

impl<T: Clone> NonEmptyVec<T> {
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

impl<T: Clone> TryFrom<Vec<T>> for NonEmptyVec<T> {
    type Error = Error;

    fn try_from(v: Vec<T>) -> Result<NonEmptyVec<T>, Error> {
        if v.is_empty() {
            bail!("cannot create a NonEmptyVec from an empty Vec")
        }
        Ok(NonEmptyVec(v))
    }
}

impl<T: Clone> From<NonEmptyVec<T>> for Vec<T> {
    fn from(NonEmptyVec(v): NonEmptyVec<T>) -> Vec<T> {
        v
    }
}

impl<T: Clone> AsRef<[T]> for NonEmptyVec<T> {
    fn as_ref(&self) -> &[T] {
        &self.0
    }
}

impl<T: Clone> Deref for NonEmptyVec<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.0
    }
}

/// String utilities for parsing and displaying humanly readable values.
pub fn to_human_readable_string(value: impl Into<String>) -> String {
    value
        .into()
        .chars()
        .fold(String::new(), |mut acc, c| {
            // Convert camelCase to space-separated words with capitalized first letter.
            if c.is_uppercase() {
                acc.push(' ');
            }

            // Check if the field is snake_case and convert to
            // space-separated words with capitalized first letter.
            if c == '_' {
                acc.push(' ');
                return acc;
            }

            acc.push(c);
            acc
        })
        // Split the path based on empty spaces and uppercase the first letter of each word.
        .split(' ')
        .fold(String::new(), |desc, word| {
            let word = word
                .chars()
                .enumerate()
                .fold(String::new(), |mut acc, (i, c)| {
                    // Capitalize the first letter of the word.
                    if i == 0 {
                        if let Some(c) = c.to_uppercase().next() {
                            acc.push(c);
                            return acc;
                        }
                    }
                    acc.push(c);
                    acc
                });

            format!("{desc} {}", word.trim_end())
        })
        .trim_end()
        .to_string()
}
