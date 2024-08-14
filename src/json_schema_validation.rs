use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

use crate::utils::NonEmptyVec;

/// The value of this keyword MUST be either a string or an array. If it is an array,
/// elements of the array MUST be strings and MUST be unique.
///
/// String values MUST be one of the six primitive types
/// ("null", "boolean", "object", "array", "number", or "string"), or "integer"
/// which matches any number with a zero fractional part.
///
/// If the value of "type" is a string, then an instance validates successfully if its
/// type matches the type represented by the value of the string. If the value of "type"
/// is an array, then an instance validates successfully if its type matches any
/// of the types indicated by the strings in the array.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SchemaType {
    String,
    Number,
    Integer,
    Boolean,
    Array,
    Object,
}

/// Schema Validator is a JSON Schema descriptor used to evaluate the return value of a JsonPath
/// expression, used by the presentation definition constraints field to ensure the property value
/// meets the expected schema.
///
/// For more information, see the field constraints filter property:
///
/// - [https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object](https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object)
///
/// - [https://json-schema.org/understanding-json-schema](https://json-schema.org/understanding-json-schema)
///
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SchemaValidator {
    #[serde(rename = "type")]
    schema_type: SchemaType,
    #[serde(rename = "minLength", skip_serializing_if = "Option::is_none")]
    min_length: Option<usize>,
    #[serde(rename = "maxLength", skip_serializing_if = "Option::is_none")]
    max_length: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pattern: Option<String>,
    // TODO: Consider using a generic type for numbers/integers that
    // can be used for minimum, maximum, exclusiveMinimum, exclusiveMaximum, multipleOf
    #[serde(skip_serializing_if = "Option::is_none")]
    minimum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    maximum: Option<f64>,
    #[serde(rename = "exclusiveMinimum", skip_serializing_if = "Option::is_none")]
    exclusive_minimum: Option<f64>,
    #[serde(rename = "exclusiveMaximum", skip_serializing_if = "Option::is_none")]
    exclusive_maximum: Option<f64>,
    #[serde(rename = "multipleOf", skip_serializing_if = "Option::is_none")]
    multiple_of: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    required: Option<Vec<String>>,
    #[serde(rename = "dependentRequired", skip_serializing_if = "Option::is_none")]
    dependent_required: Option<HashMap<String, Vec<String>>>,
    #[serde(rename = "maxProperties", skip_serializing_if = "Option::is_none")]
    max_properties: Option<usize>,
    #[serde(rename = "minProperties", skip_serializing_if = "Option::is_none")]
    min_properties: Option<usize>,
    #[serde(rename = "maxItems", skip_serializing_if = "Option::is_none")]
    max_items: Option<usize>,
    #[serde(rename = "minItems", skip_serializing_if = "Option::is_none")]
    min_items: Option<usize>,
    #[serde(rename = "uniqueItems", skip_serializing_if = "Option::is_none")]
    unique_items: Option<bool>,
    #[serde(rename = "maxContains", skip_serializing_if = "Option::is_none")]
    max_contains: Option<usize>,
    #[serde(rename = "contains", skip_serializing_if = "Option::is_none")]
    contains: Option<SchemaType>,
    #[serde(rename = "minContains", skip_serializing_if = "Option::is_none")]
    min_contains: Option<usize>,
    #[serde(rename = "const", skip_serializing_if = "Option::is_none")]
    r#const: Option<Value>,
    #[serde(rename = "enum", skip_serializing_if = "Option::is_none")]
    r#enum: Option<NonEmptyVec<Value>>,
}

impl PartialEq for SchemaValidator {
    fn eq(&self, other: &Self) -> bool {
        self.schema_type == other.schema_type
            && self.min_length == other.min_length
            && self.max_length == other.max_length
            && self.pattern == other.pattern
            && self.minimum == other.minimum
            && self.maximum == other.maximum
            && self.required == other.required
            && self.dependent_required == other.dependent_required
            && self.max_properties == other.max_properties
            && self.min_properties == other.min_properties
            && self.max_items == other.max_items
            && self.min_items == other.min_items
            && self.unique_items == other.unique_items
            && self.min_contains == other.min_contains
            && self.max_contains == other.max_contains
            && self.exclusive_minimum == other.exclusive_minimum
            && self.exclusive_maximum == other.exclusive_maximum
            && self.multiple_of == other.multiple_of
            && self.r#const == other.r#const
    }
}

impl Eq for SchemaValidator {}

impl SchemaValidator {
    /// Creates a new schema validator with the given schema type.
    ///
    /// A schema validator must have a schema type.
    pub fn new(schema_type: SchemaType) -> Self {
        Self {
            schema_type,
            min_length: None,
            max_length: None,
            pattern: None,
            minimum: None,
            maximum: None,
            exclusive_minimum: None,
            exclusive_maximum: None,
            multiple_of: None,
            required: None,
            dependent_required: None,
            max_properties: None,
            min_properties: None,
            max_items: None,
            min_items: None,
            unique_items: None,
            min_contains: None,
            max_contains: None,
            contains: None,
            r#const: None,
            r#enum: None,
        }
    }

    /// The value of this keyword MUST be a non-negative integer.
    ///
    /// An array instance is valid against "maxItems" if its size is less than, or equal to, the value of this keyword.
    ///
    /// See: [https://json-schema.org/draft/2020-12/json-schema-validation#section-6.4.1](https://json-schema.org/draft/2020-12/json-schema-validation#section-6.4.1)
    pub fn set_max_items(mut self, max_items: usize) -> Self {
        self.max_items = Some(max_items);
        self
    }

    /// The value of this keyword MUST be a non-negative integer.
    ///
    /// An array instance is valid against "minItems" if its size is greater than, or equal to, the value of this keyword.
    ///
    /// Omitting this keyword has the same behavior as a value of 0.
    ///
    /// See: [https://json-schema.org/draft/2020-12/json-schema-validation#section-6.4.2](https://json-schema.org/draft/2020-12/json-schema-validation#section-6.4.2)
    pub fn set_min_items(mut self, min_items: usize) -> Self {
        self.min_items = Some(min_items);
        self
    }

    /// The value of this keyword MUST be a boolean.
    ///
    /// If this keyword has boolean value false, the instance validates successfully.
    /// If it has boolean value true, the instance validates successfully if all of its elements are unique.
    ///
    /// Omitting this keyword has the same behavior as a value of false.
    ///
    /// See: [https://json-schema.org/draft/2020-12/json-schema-validation#section-6.4.3](https://json-schema.org/draft/2020-12/json-schema-validation#section-6.4.3)
    pub fn set_unique_items(mut self, unique_items: bool) -> Self {
        self.unique_items = Some(unique_items);
        self
    }

    /// The value of this keyword MUST be a non-negative integer.
    ///
    /// If "contains" is not present within the same schema object, then this keyword has no effect.
    ///
    /// An instance array is valid against "maxContains" in two ways, depending on the form of the
    /// annotation result of an adjacent "contains" [json-schema] keyword. The first way is if the
    /// annotation result is an array and the length of that array is less than or equal to the "maxContains"
    /// value. The second way is if the annotation result is a boolean "true" and the instance array length
    /// is less than or equal to the "maxContains" value.
    ///
    /// See: [https://json-schema.org/draft/2020-12/json-schema-validation#section-6.4.4](https://json-schema.org/draft/2020-12/json-schema-validation#section-6.4.4)
    pub fn set_max_contains(mut self, max: usize, contains: SchemaType) -> Self {
        self.max_contains = Some(max);
        self.contains = Some(contains);
        self
    }

    /// The value of this keyword MUST be a non-negative integer.
    ///
    /// If "contains" is not present within the same schema object, then this keyword has no effect.
    ///
    /// An instance array is valid against "minContains" in two ways, depending on the form of the annotation result of an adjacent "contains" [json-schema] keyword. The first way is if the annotation result is an array and the length of that array is greater than or equal to the "minContains" value. The second way is if the annotation result is a boolean "true" and the instance array length is greater than or equal to the "minContains" value.
    ///
    /// A value of 0 is allowed, but is only useful for setting a range of occurrences from 0 to the value of "maxContains". A value of 0 causes "minContains" and "contains" to always pass validation (but validation can still fail against a "maxContains" keyword).
    ///
    /// Omitting this keyword has the same behavior as a value of 1.
    ///
    /// See: [https://json-schema.org/draft/2020-12/json-schema-validation#section-6.4.5](https://json-schema.org/draft/2020-12/json-schema-validation#section-6.4.5)
    pub fn set_min_contains(mut self, min: usize, contains: SchemaType) -> Self {
        self.min_contains = Some(min);
        self.contains = Some(contains);
        self
    }

    /// The value of "minimum" MUST be a number, representing an inclusive lower limit for a numeric instance.
    ///
    /// If the instance is a number, then this keyword validates only if the instance is greater than or exactly equal to "minimum".
    ///
    /// See: [https://json-schema.org/draft/2020-12/json-schema-validation#section-6.2.4](https://json-schema.org/draft/2020-12/json-schema-validation#section-6.2.4)
    pub fn set_minimum(mut self, minimum: f64) -> Self {
        self.minimum = Some(minimum);
        self
    }

    /// The value of "maximum" MUST be a number, representing an inclusive upper limit for a numeric instance.
    ///
    /// If the instance is a number, then this keyword validates only if the instance is less than or exactly equal to "maximum".
    ///
    /// See: [https://json-schema.org/draft/2020-12/json-schema-validation#section-6.2.2](https://json-schema.org/draft/2020-12/json-schema-validation#section-6.2.2)
    pub fn set_maximum(mut self, maximum: f64) -> Self {
        self.maximum = Some(maximum);
        self
    }

    /// The value of "exclusiveMinimum" MUST be a number, representing an exclusive lower limit for a numeric instance.
    ///
    /// If the instance is a number, then the instance is valid only if it has a value strictly greater than (not equal to) "exclusiveMinimum".
    ///
    /// See: [https://json-schema.org/draft/2020-12/json-schema-validation#section-6.2.5](https://json-schema.org/draft/2020-12/json-schema-validation#section-6.2.5)
    pub fn set_exclusive_minimum(mut self, exclusive_minimum: f64) -> Self {
        self.exclusive_minimum = Some(exclusive_minimum);
        self
    }

    /// The value of "exclusiveMaximum" MUST be a number, representing an exclusive upper limit for a numeric instance.
    ///
    /// If the instance is a number, then the instance is valid only if it has a value strictly less than (not equal to) "exclusiveMaximum".
    ///
    /// See: [https://json-schema.org/draft/2020-12/json-schema-validation#section-6.2.3](https://json-schema.org/draft/2020-12/json-schema-validation#section-6.2.3)
    pub fn set_exclusive_maximum(mut self, exclusive_maximum: f64) -> Self {
        self.exclusive_maximum = Some(exclusive_maximum);
        self
    }

    /// The value of "exclusiveMinimum" MUST be a number, representing an exclusive lower limit for a numeric instance.
    ///
    /// If the instance is a number, then the instance is valid only if it has a value strictly greater than (not equal to) "exclusiveMinimum".
    ///
    /// See: [https://json-schema.org/draft/2020-12/json-schema-validation#section-6.2.1](https://json-schema.org/draft/2020-12/json-schema-validation#section-6.2.1)
    pub fn set_multiple_of(mut self, multiple_of: f64) -> Self {
        self.multiple_of = Some(multiple_of);
        self
    }

    /// The value of this keyword MUST be an array. Elements of this array, if any, MUST be strings, and MUST be unique.
    ///
    /// An object instance is valid against this keyword if every item in the array is the name of a property in the instance.
    ///
    /// Omitting this keyword has the same behavior as an empty array.
    ///
    /// See: [https://json-schema.org/draft/2020-12/json-schema-validation#section-6.5.3](https://json-schema.org/draft/2020-12/json-schema-validation#section-6.5.3)
    pub fn set_required(mut self, required: Vec<String>) -> Self {
        self.required = Some(required);
        self
    }

    /// Push a single requirement to the list of required properties.
    pub fn add_requirement(mut self, requirement: String) -> Self {
        self.required.get_or_insert_with(Vec::new).push(requirement);
        self
    }

    /// Set the dependent requirements for a property.
    pub fn set_dependent_requirements(
        mut self,
        dependent_requirements: HashMap<String, Vec<String>>,
    ) -> Self {
        self.dependent_required = Some(dependent_requirements);
        self
    }

    /// Add a dependent requirement for a property.
    pub fn add_dependent_requirement(mut self, property: String, requirement: Vec<String>) -> Self {
        self.dependent_required
            .get_or_insert_with(HashMap::new)
            .insert(property, requirement);
        self
    }

    /// The value of this keyword MUST be a non-negative integer.
    ///
    /// An object instance is valid against "maxProperties" if its number of properties is less than, or equal to, the value of this keyword.
    ///
    /// See: [https://json-schema.org/draft/2020-12/json-schema-validation#section-6.5.1](https://json-schema.org/draft/2020-12/json-schema-validation#section-6.5.1)
    pub fn set_max_properties(mut self, max_properties: usize) -> Self {
        self.max_properties = Some(max_properties);
        self
    }

    /// The value of this keyword MUST be a non-negative integer.
    ///
    /// An object instance is valid against "minProperties" if its number of properties is greater than, or equal to, the value of this keyword.
    ///
    /// Omitting this keyword has the same behavior as a value of 0.
    ///
    /// See: [https://json-schema.org/draft/2020-12/json-schema-validation#section-6.5.2](https://json-schema.org/draft/2020-12/json-schema-validation#section-6.5.2)
    pub fn set_min_properties(mut self, min_properties: usize) -> Self {
        self.min_properties = Some(min_properties);
        self
    }

    /// The value of this keyword MUST be a non-negative integer.
    ///
    /// A string instance is valid against this keyword if its length is greater than, or equal to, the value of this keyword.
    ///
    /// The length of a string instance is defined as the number of its characters as defined by RFC 8259 [RFC8259].
    ///
    /// Omitting this keyword has the same behavior as a value of 0.
    ///
    /// See: [https://json-schema.org/draft/2020-12/json-schema-validation#section-6.3.2](https://json-schema.org/draft/2020-12/json-schema-validation#section-6.3.2)
    pub fn set_min_length(mut self, min_length: usize) -> Self {
        self.min_length = Some(min_length);
        self
    }

    /// The value of this keyword MUST be a non-negative integer.
    ///
    /// A string instance is valid against this keyword if its length is less than, or equal to, the value of this keyword.
    ///
    /// The length of a string instance is defined as the number of its characters as defined by RFC 8259 [RFC8259].
    ///
    /// See: [https://json-schema.org/draft/2020-12/json-schema-validation#section-6.3.1](https://json-schema.org/draft/2020-12/json-schema-validation#section-6.3.1)
    pub fn set_max_length(mut self, max_length: usize) -> Self {
        self.max_length = Some(max_length);
        self
    }

    /// The value of this keyword MUST be a string. This string SHOULD be a valid regular expression, according to the ECMA-262 regular expression dialect.

    // A string instance is considered valid if the regular expression matches the instance successfully.
    // Recall: regular expressions are not implicitly anchored.
    //
    // See: [https://json-schema.org/draft/2020-12/json-schema-validation#section-6.3.3](https://json-schema.org/draft/2020-12/json-schema-validation#section-6.3.3)
    pub fn set_pattern(mut self, pattern: String) -> Self {
        self.pattern = Some(pattern);
        self
    }

    /// The value of this keyword MUST be an array. This array SHOULD have at least one element. Elements in the array SHOULD be unique.
    ///
    /// An instance validates successfully against this keyword if its value is equal to one of the elements in this keyword's array value.
    ///
    /// Elements in the array might be of any type, including null.
    ///
    /// https://json-schema.org/draft/2020-12/json-schema-validation#section-6.1.2
    pub fn set_enum(mut self, r#enum: NonEmptyVec<Value>) -> Self {
        self.r#enum = Some(r#enum);
        self
    }

    /// The value of this keyword MAY be of any type, including null.
    /// Use of this keyword is functionally equivalent to an "enum" (Section 6.1.2) with a single value.
    /// An instance validates successfully against this keyword if its value is equal to the value of the keyword.
    pub fn set_const(mut self, r#const: Value) -> Self {
        self.r#const = Some(r#const);
        self
    }

    /// Primary method for validating a JSON value against the schema.
    pub fn validate(&self, value: &Value) -> Result<()> {
        // Check input against const, if it exists.
        if let Some(const_value) = self.r#const.as_ref() {
            if value != const_value {
                bail!("Value does not match const");
            }
        }

        // Check input against enum, if it exists.
        if let Some(enum_values) = self.r#enum.as_ref() {
            if !enum_values.contains(value) {
                bail!("Value does not match enum");
            }
        }

        match self.schema_type {
            SchemaType::String => self.validate_string(value),
            SchemaType::Number => self.validate_number(value),
            SchemaType::Integer => self.validate_integer(value),
            SchemaType::Boolean => self.validate_boolean(value),
            SchemaType::Array => self.validate_array(value),
            SchemaType::Object => self.validate_object(value),
        }
    }

    pub fn validate_string(&self, value: &Value) -> Result<()> {
        let s = value.as_str().context("Expected a string")?;

        if let Some(min_length) = self.min_length {
            if s.len() < min_length {
                bail!(
                    "String length {} is less than minimum {}",
                    s.len(),
                    min_length
                );
            }
        }

        if let Some(max_length) = self.max_length {
            if s.len() > max_length {
                bail!(
                    "String length {} is greater than maximum {}",
                    s.len(),
                    max_length
                );
            }
        }

        if let Some(pattern) = self.pattern.as_ref() {
            let regex_pattern = Regex::new(pattern).context("Invalid regex pattern")?;

            if !regex_pattern.is_match(s) {
                bail!("String {s} does not match pattern: {}", regex_pattern);
            }
        }

        Ok(())
    }

    pub fn validate_number(&self, value: &Value) -> Result<()> {
        let n = value.as_f64().context("Expected a number")?;

        if let Some(minimum) = self.minimum {
            if n < minimum {
                bail!("Number {} is less than minimum {}", n, minimum);
            }
        }

        if let Some(maximum) = self.maximum {
            if n > maximum {
                bail!("Number {} is greater than maximum {}", n, maximum);
            }
        }

        if let Some(exclusive_minimum) = self.exclusive_minimum {
            if n <= exclusive_minimum {
                bail!(
                    "Number {} is less than or equal to exclusive minimum {}",
                    n,
                    exclusive_minimum
                );
            }
        }

        if let Some(exclusive_maximum) = self.exclusive_maximum {
            if n >= exclusive_maximum {
                bail!(
                    "Number {} is greater than or equal to exclusive maximum {}",
                    n,
                    exclusive_maximum
                );
            }
        }

        if let Some(multiple_of) = self.multiple_of {
            if n % multiple_of != 0.0 {
                bail!("Number {} is not a multiple of {}", n, multiple_of);
            }
        }

        Ok(())
    }

    pub fn validate_integer(&self, value: &Value) -> Result<()> {
        let n = value.as_i64().context("Expected an integer")?;

        if let Some(minimum) = self.minimum {
            if n < minimum as i64 {
                bail!("Integer {} is less than minimum {}", n, minimum);
            }
        }

        if let Some(maximum) = self.maximum {
            if n > maximum as i64 {
                bail!("Integer {} is greater than maximum {}", n, maximum);
            }
        }

        if let Some(exclusive_minimum) = self.exclusive_minimum {
            if n <= exclusive_minimum as i64 {
                bail!(
                    "Integer {} is less than or equal to exclusive minimum {}",
                    n,
                    exclusive_minimum
                );
            }
        }

        if let Some(exclusive_maximum) = self.exclusive_maximum {
            if n >= exclusive_maximum as i64 {
                bail!(
                    "Integer {} is greater than or equal to exclusive maximum {}",
                    n,
                    exclusive_maximum
                );
            }
        }

        if let Some(multiple_of) = self.multiple_of {
            if n % multiple_of as i64 != 0 {
                bail!("Integer {} is not a multiple of {}", n, multiple_of);
            }
        }

        Ok(())
    }

    pub fn validate_boolean(&self, value: &Value) -> Result<()> {
        if !value.is_boolean() {
            bail!("Expected a boolean".to_string());
        }
        Ok(())
    }

    pub fn validate_array(&self, value: &Value) -> Result<()> {
        let arr = value.as_array().context("Expected an array")?;

        if let Some(min_items) = self.min_items {
            if arr.len() < min_items {
                bail!(
                    "Array length {} is less than minimum {}",
                    arr.len(),
                    min_items
                );
            }
        }

        if let Some(max_items) = self.max_items {
            if arr.len() > max_items {
                bail!(
                    "Array length {} is greater than maximum {}",
                    arr.len(),
                    max_items
                );
            }
        }

        if let Some(unique_items) = self.unique_items {
            if unique_items {
                let mut unique = HashSet::new();
                for item in arr {
                    if !unique.insert(item) {
                        bail!("Array has duplicate items");
                    }
                }
            }
        }

        if let Some(contains) = self.contains.as_ref() {
            match contains {
                SchemaType::String => {
                    let count = arr.iter().filter(|item| item.is_string()).count();

                    if let Some(max_contains) = self.max_contains {
                        if count > max_contains {
                            bail!("Array contains more than maximum number of strings");
                        }
                    }

                    if let Some(min_contains) = self.min_contains {
                        if count < min_contains {
                            bail!("Array contains fewer than minimum number of strings");
                        }
                    }
                }
                SchemaType::Number => {
                    let count = arr.iter().filter(|item| item.is_number()).count();

                    if let Some(max_contains) = self.max_contains {
                        if count > max_contains {
                            bail!("Array contains more than maximum number of numbers");
                        }
                    }

                    if let Some(min_contains) = self.min_contains {
                        if count < min_contains {
                            bail!("Array contains fewer than minimum number of numbers");
                        }
                    }
                }
                SchemaType::Integer => {
                    let count = arr.iter().filter(|item| item.is_i64()).count();

                    if let Some(max_contains) = self.max_contains {
                        if count > max_contains {
                            bail!("Array contains more than maximum number of integers");
                        }
                    }

                    if let Some(min_contains) = self.min_contains {
                        if count < min_contains {
                            bail!("Array contains fewer than minimum number of integers");
                        }
                    }
                }
                SchemaType::Boolean => {
                    let count = arr.iter().filter(|item| item.is_boolean()).count();

                    if let Some(max_contains) = self.max_contains {
                        if count > max_contains {
                            bail!("Array contains more than maximum number of booleans");
                        }
                    }

                    if let Some(min_contains) = self.min_contains {
                        if count < min_contains {
                            bail!("Array contains fewer than minimum number of booleans");
                        }
                    }
                }
                SchemaType::Array => {
                    let count = arr.iter().filter(|item| item.is_array()).count();

                    if let Some(max_contains) = self.max_contains {
                        if count > max_contains {
                            bail!("Array contains more than maximum number of arrays");
                        }
                    }

                    if let Some(min_contains) = self.min_contains {
                        if count < min_contains {
                            bail!("Array contains fewer than minimum number of arrays");
                        }
                    }
                }
                SchemaType::Object => {
                    let count = arr.iter().filter(|item| item.is_object()).count();

                    if let Some(max_contains) = self.max_contains {
                        if count > max_contains {
                            bail!("Array contains more than maximum number of objects");
                        }
                    }

                    if let Some(min_contains) = self.min_contains {
                        if count < min_contains {
                            bail!("Array contains fewer than minimum number of objects");
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub fn validate_object(&self, value: &Value) -> Result<()> {
        let obj = value.as_object().context("Expected an object")?;

        if let Some(required) = &self.required {
            for required_prop in required {
                if !obj.contains_key(required_prop) {
                    bail!("Missing required property: {}", required_prop);
                }
            }
        }

        if let Some(min_properties) = self.min_properties {
            if obj.len() < min_properties {
                bail!(
                    "Object has fewer properties {} than minimum {}",
                    obj.len(),
                    min_properties
                );
            }
        }

        if let Some(max_properties) = self.max_properties {
            if obj.len() > max_properties {
                bail!(
                    "Object has more properties {} than maximum {}",
                    obj.len(),
                    max_properties
                );
            }
        }

        if let Some(dependents_required) = &self.dependent_required {
            for (prop, dependents) in dependents_required {
                if let Some(obj) = obj.get(prop) {
                    let child = obj.as_object().context("Expected an object")?;

                    for dependent in dependents {
                        if !child.contains_key(dependent) {
                            bail!("Dependent property {} is required", dependent);
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn test_regex() -> Result<()> {
        let regex = Regex::new(r#"(\+1|1)?[-.\s]?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}"#)?;

        assert!(regex.is_match(r#"+1 (253) 111 4321"#));

        Ok(())
    }

    #[test]
    fn test_validate_string() -> Result<()> {
        let value = Value::String("hello".to_string());

        let mut schema_validator = SchemaValidator::new(SchemaType::String).set_max_length(4);

        assert!(schema_validator.validate(&value).is_err());

        schema_validator = schema_validator.set_max_length(5);

        assert!(schema_validator.validate(&value).is_ok());

        schema_validator = schema_validator
            .set_pattern(r#"(\+1|1)?[-.\s]?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}"#.to_owned());

        assert!(schema_validator.validate(&value).is_err());
        schema_validator = schema_validator.set_max_length(17);

        let value = Value::String(r#"+1 (253) 111 4321"#.to_owned());

        assert!(schema_validator.validate(&value).is_ok());

        Ok(())
    }

    #[test]
    fn test_validate_number() -> Result<()> {
        let mut schema_validator = SchemaValidator::new(SchemaType::Number);

        let mut value = serde_json::json!(5.0);

        assert!(schema_validator.validate(&value).is_ok());

        schema_validator = schema_validator.set_minimum(6.0).set_maximum(9.0);

        assert!(schema_validator.validate(&value).is_err());

        value = serde_json::json!(6.0);

        assert!(schema_validator.validate(&value).is_ok());

        schema_validator = schema_validator
            .set_exclusive_minimum(6.0)
            .set_exclusive_maximum(9.0);

        assert!(schema_validator.validate(&value).is_err());

        value = serde_json::json!(7.0);

        assert!(schema_validator.validate(&value).is_ok());

        schema_validator = schema_validator.set_multiple_of(2.0);

        assert!(schema_validator.validate(&value).is_err());

        value = serde_json::json!(8.0);

        assert!(schema_validator.validate(&value).is_ok());

        Ok(())
    }

    #[test]
    fn test_validate_integer() -> Result<()> {
        let mut schema_validator = SchemaValidator::new(SchemaType::Integer);

        let mut value = serde_json::json!(5);

        assert!(schema_validator.validate(&value).is_ok());

        schema_validator = schema_validator.set_minimum(6.).set_maximum(9.);

        assert!(schema_validator.validate(&value).is_err());

        value = serde_json::json!(6);

        assert!(schema_validator.validate(&value).is_ok());

        schema_validator = schema_validator
            .set_exclusive_minimum(6.)
            .set_exclusive_maximum(9.);

        assert!(schema_validator.validate(&value).is_err());

        value = serde_json::json!(7);

        assert!(schema_validator.validate(&value).is_ok());

        schema_validator = schema_validator.set_multiple_of(2.);

        assert!(schema_validator.validate(&value).is_err());

        value = serde_json::json!(8);

        assert!(schema_validator.validate(&value).is_ok());

        Ok(())
    }

    #[test]
    fn test_validate_array() -> Result<()> {
        let mut schema_validator = SchemaValidator::new(SchemaType::Array);

        let mut value = serde_json::json!([1, 2, 3]);

        assert!(schema_validator.validate(&value).is_ok());

        schema_validator = schema_validator.set_min_items(4);

        assert!(schema_validator.validate(&value).is_err());

        schema_validator = schema_validator.set_max_items(5);

        value = serde_json::json!([1, 2, 3, 4, 5]);

        assert!(schema_validator.validate(&value).is_ok());

        schema_validator = schema_validator.set_unique_items(true);

        value = serde_json::json!([1, 2, 3, 5, 5]);

        assert!(schema_validator.validate(&value).is_err());

        schema_validator = schema_validator.set_unique_items(false);

        assert!(schema_validator.validate(&value).is_ok());

        schema_validator = schema_validator.set_min_contains(1, SchemaType::String);

        assert!(schema_validator.validate(&value).is_err());

        value = serde_json::json!([1, 2, 3, "Hello", ["a", "b", "c"]]);

        assert!(schema_validator.validate(&value).is_ok());

        // NOTE: To check whether an array contains multiple different typed elements,
        // we can overwrite the `min/max_contains` value to check for a new type.
        schema_validator = schema_validator.set_min_contains(1, SchemaType::Array);

        assert!(schema_validator.validate(&value).is_ok());

        schema_validator = schema_validator.set_min_contains(3, SchemaType::Number);

        assert!(schema_validator.validate(&value).is_ok());

        Ok(())
    }

    #[test]
    fn test_validate_object() -> Result<()> {
        let mut schema_validator = SchemaValidator::new(SchemaType::Object);

        let value = serde_json::json!({
            "name": "John Doe",
            "age": 25,
            "address": {
                "street": "1234 Elm St",
                "city": "Springfield",
                "state": "IL",
                "zip": "62701"
            }
        });

        assert!(schema_validator.validate(&value).is_ok());

        schema_validator = schema_validator.set_min_properties(5);

        assert!(schema_validator.validate(&value).is_err());

        schema_validator = schema_validator.set_min_properties(3);

        assert!(schema_validator.validate(&value).is_ok());

        schema_validator = schema_validator.add_requirement("birthdate".into());

        assert!(schema_validator.validate(&value).is_err());

        // NOTE: `set_required` will overwrite existing required fields.
        schema_validator =
            schema_validator.set_required(vec!["name".into(), "age".into(), "address".into()]);

        assert!(schema_validator.validate(&value).is_ok());

        schema_validator =
            schema_validator.add_dependent_requirement("address".into(), vec!["street".into()]);

        assert!(schema_validator.validate(&value).is_ok());

        // NOTE: `add_requirement` will add to the existing required fields.
        schema_validator = schema_validator.add_requirement("birthdate".into());

        assert!(schema_validator.validate(&value).is_err());

        Ok(())
    }

    #[test]
    fn test_const() -> Result<()> {
        let mut schema_validator = SchemaValidator::new(SchemaType::String);

        let value = serde_json::json!("Hello, world!");

        assert!(schema_validator.validate(&value).is_ok());

        schema_validator = schema_validator.set_const(serde_json::json!("Hello, World!"));

        assert!(schema_validator.validate(&value).is_err());

        Ok(())
    }

    #[test]
    fn test_enum() -> Result<()> {
        let mut schema_validator = SchemaValidator::new(SchemaType::String);

        let value = serde_json::json!("Hello, world!");

        assert!(schema_validator.validate(&value).is_ok());

        let mut enums = NonEmptyVec::new(serde_json::json!("Hello, World!"));

        schema_validator = schema_validator.set_enum(enums.clone());

        assert!(schema_validator.validate(&value).is_err());

        enums.push(serde_json::json!("Hello, world!"));
        schema_validator = schema_validator.set_enum(enums);

        assert!(schema_validator.validate(&value).is_ok());

        Ok(())
    }
}
