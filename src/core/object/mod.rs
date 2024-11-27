use anyhow::{Context, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json};

/// An untyped (JSON) Object from which [TypedParameters](TypedParameter) can be parsed.
///
/// Can represent metadata or request objects.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UntypedObject(pub(crate) Map<String, Json>);

// TODO: Replace anyhow error type.
/// A strongly typed parameter that can represent metadata entries or request parameters.
pub trait TypedParameter:
    TryFrom<Json, Error = anyhow::Error> + TryInto<Json> + Clone + std::fmt::Debug
{
    const KEY: &'static str;
}

impl UntypedObject {
    /// Get a [TypedParameter] from the Object or return the default value.
    ///
    /// Note that this method clones the underlying data.
    pub fn get_or_default<T: TypedParameter + Default>(&self) -> Result<T> {
        Ok(self
            .0
            .get(T::KEY)
            .cloned()
            .map(TryInto::try_into)
            .transpose()?
            .unwrap_or_default())
    }

    /// Get a [TypedParameter] from the Object.
    ///
    /// Note that this method clones the underlying data.
    pub fn get<T: TypedParameter>(&self) -> Option<Result<T>> {
        Some(self.0.get(T::KEY)?.clone().try_into().map_err(Into::into))
    }

    /// Remove a [TypedParameter] from the Object.
    pub fn remove<T: TypedParameter>(&mut self) -> Option<Result<T>> {
        Some(self.0.remove(T::KEY)?.try_into().map_err(Into::into))
    }

    /// Insert a [TypedParameter].
    ///
    /// Returns the existing [TypedParameter] if one already exists.
    ///
    /// # Errors
    /// Returns an error if there was already an entry in the Object, but it could not be parsed from JSON.
    pub fn insert<T: TypedParameter>(&mut self, t: T) -> Option<Result<T>> {
        match t.try_into() {
            Err(_) => Some(Err(Error::msg("failed to parse typed parameter"))),
            Ok(value) => Some(
                self.0
                    .insert(T::KEY.to_owned(), value)?
                    .try_into()
                    .map_err(Into::into),
            ),
        }
    }
}

impl From<UntypedObject> for Json {
    fn from(value: UntypedObject) -> Self {
        value.0.into()
    }
}

pub trait ParsingErrorContext {
    type T: TypedParameter;

    fn parsing_error(self) -> Result<Self::T>;
}

impl<T: TypedParameter> ParsingErrorContext for Option<Result<T>> {
    type T = T;

    fn parsing_error(self) -> Result<T> {
        self.context(format!("'{}' is missing", T::KEY))?
            .context(format!("'{}' could not be parsed", T::KEY))
    }
}

impl<T: TypedParameter> ParsingErrorContext for Result<T> {
    type T = T;

    fn parsing_error(self) -> Result<T> {
        self.context(format!("'{}' could not be parsed", T::KEY))
    }
}
