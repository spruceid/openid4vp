use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

// TODO: Consider using `Value` type from `serde_json`
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
/// https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SchemaValidator {
    #[serde(rename = "type")]
    schema_type: SchemaType,
    #[serde(skip_serializing_if = "Option::is_none")]
    min_length: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_length: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    minimum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    maximum: Option<f64>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    required: Vec<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    properties: HashMap<String, Box<SchemaValidator>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    items: Option<Box<SchemaValidator>>,
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
            && self.properties == other.properties
            && self.items == other.items
    }
}

impl Eq for SchemaValidator {}

impl SchemaValidator {
    pub fn validate(&self, value: &Value) -> Result<()> {
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

        if let Some(pattern) = &self.pattern {
            // Note: In a real implementation, you'd use a regex library here
            if !s.contains(pattern) {
                bail!("String does not match pattern: {}", pattern);
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

        Ok(())
    }

    pub fn validate_integer(&self, value: &Value) -> Result<()> {
        let n = value.as_i64().context("Expected an integer")?;

        if let Some(minimum) = self.minimum {
            if (n as f64) < minimum {
                bail!("Integer {} is less than minimum {}", n, minimum);
            }
        }

        if let Some(maximum) = self.maximum {
            if n as f64 > maximum {
                bail!("Integer {} is greater than maximum {}", n, maximum);
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

        if let Some(min_length) = self.min_length {
            if arr.len() < min_length {
                bail!(
                    "Array length {} is less than minimum {}",
                    arr.len(),
                    min_length
                );
            }
        }

        if let Some(max_length) = self.max_length {
            if arr.len() > max_length {
                bail!(
                    "Array length {} is greater than maximum {}",
                    arr.len(),
                    max_length
                );
            }
        }

        if let Some(item_validator) = &self.items {
            for (index, item) in arr.iter().enumerate() {
                item_validator
                    .validate(item)
                    .context(format!("Error in array item {}", index))?;
            }
        }

        Ok(())
    }

    pub fn validate_object(&self, value: &Value) -> Result<()> {
        let obj = value.as_object().context("Expected an object")?;

        for required_prop in &self.required {
            if !obj.contains_key(required_prop) {
                bail!("Missing required property: {}", required_prop);
            }
        }

        for (prop_name, prop_validator) in &self.properties {
            if let Some(prop_value) = obj.get(prop_name) {
                prop_validator
                    .validate(prop_value)
                    .context(format!("Error in property {}", prop_name))?;
            }
        }

        Ok(())
    }
}
