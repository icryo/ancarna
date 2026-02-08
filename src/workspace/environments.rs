//! Environment management

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An environment with variables
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Environment {
    /// Environment ID
    pub id: String,

    /// Environment name
    pub name: String,

    /// Variables in this environment
    pub variables: Vec<Variable>,

    /// Whether this is the global environment
    #[serde(default)]
    pub is_global: bool,
}

/// A variable in an environment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Variable {
    /// Variable name
    pub name: String,

    /// Variable value
    pub value: String,

    /// Description
    pub description: Option<String>,

    /// Whether this is a secret (should be masked)
    #[serde(default)]
    pub is_secret: bool,

    /// Whether the variable is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

impl Environment {
    /// Create a new environment
    pub fn new(name: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            variables: Vec::new(),
            is_global: false,
        }
    }

    /// Create a global environment
    pub fn global() -> Self {
        Self {
            id: "global".to_string(),
            name: "Global".to_string(),
            variables: Vec::new(),
            is_global: true,
        }
    }

    /// Add a variable
    pub fn add_variable(&mut self, name: &str, value: &str) {
        self.variables.push(Variable {
            name: name.to_string(),
            value: value.to_string(),
            description: None,
            is_secret: false,
            enabled: true,
        });
    }

    /// Add a secret variable
    pub fn add_secret(&mut self, name: &str, value: &str) {
        self.variables.push(Variable {
            name: name.to_string(),
            value: value.to_string(),
            description: None,
            is_secret: true,
            enabled: true,
        });
    }

    /// Get a variable value
    pub fn get(&self, name: &str) -> Option<String> {
        self.variables
            .iter()
            .find(|v| v.name == name && v.enabled)
            .map(|v| v.value.clone())
    }

    /// Set a variable value
    pub fn set(&mut self, name: &str, value: &str) {
        if let Some(var) = self.variables.iter_mut().find(|v| v.name == name) {
            var.value = value.to_string();
        } else {
            self.add_variable(name, value);
        }
    }

    /// Remove a variable
    pub fn remove(&mut self, name: &str) {
        self.variables.retain(|v| v.name != name);
    }

    /// Convert to HashMap
    pub fn to_map(&self) -> HashMap<String, String> {
        self.variables
            .iter()
            .filter(|v| v.enabled)
            .map(|v| (v.name.clone(), v.value.clone()))
            .collect()
    }

    /// Apply variable substitution to a string
    pub fn substitute(&self, input: &str) -> String {
        let mut result = input.to_string();

        for var in &self.variables {
            if var.enabled {
                // Support both {{var}} and ${var} syntax
                result = result.replace(&format!("{{{{{}}}}}", var.name), &var.value);
                result = result.replace(&format!("${{{}}}", var.name), &var.value);
            }
        }

        result
    }
}

impl Variable {
    pub fn new(name: &str, value: &str) -> Self {
        Self {
            name: name.to_string(),
            value: value.to_string(),
            description: None,
            is_secret: false,
            enabled: true,
        }
    }
}
