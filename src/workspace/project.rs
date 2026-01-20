//! Project management

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::collections::Collection;
use super::environments::Environment;

/// A project containing collections and settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    /// Project ID
    pub id: String,

    /// Project name
    pub name: String,

    /// Project description
    pub description: Option<String>,

    /// Collections in the project
    pub collections: Vec<Collection>,

    /// Environments
    pub environments: Vec<Environment>,

    /// Global environment
    pub global: Environment,

    /// Project settings
    pub settings: ProjectSettings,

    /// Project file path (if saved)
    #[serde(skip)]
    pub file_path: Option<PathBuf>,
}

/// Project-level settings
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectSettings {
    /// Default environment name
    pub default_environment: Option<String>,

    /// Proxy settings
    pub proxy: Option<String>,

    /// Request timeout
    pub timeout: Option<u64>,

    /// Follow redirects
    pub follow_redirects: Option<bool>,

    /// Verify SSL
    pub verify_ssl: Option<bool>,
}

impl Project {
    /// Create a new project
    pub fn new(name: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: None,
            collections: Vec::new(),
            environments: Vec::new(),
            global: Environment::global(),
            settings: ProjectSettings::default(),
            file_path: None,
        }
    }

    /// Load a project from file
    pub fn load(path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read project file: {:?}", path))?;

        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");

        let mut project: Project = match ext {
            "yaml" | "yml" => serde_yaml::from_str(&content)?,
            "json" => serde_json::from_str(&content)?,
            _ => return Err(anyhow::anyhow!("Unsupported project format: {}", ext)),
        };

        project.file_path = Some(path.clone());
        Ok(project)
    }

    /// Save the project to file
    pub fn save(&self) -> Result<()> {
        let path = self
            .file_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No file path set for project"))?;

        self.save_to(path)
    }

    /// Save the project to a specific path
    pub fn save_to(&self, path: &PathBuf) -> Result<()> {
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("json");

        let content = match ext {
            "yaml" | "yml" => serde_yaml::to_string(self)?,
            "json" => serde_json::to_string_pretty(self)?,
            _ => return Err(anyhow::anyhow!("Unsupported format: {}", ext)),
        };

        std::fs::write(path, content)?;
        Ok(())
    }

    /// Add a collection
    pub fn add_collection(&mut self, collection: Collection) {
        self.collections.push(collection);
    }

    /// Create and add a new collection
    pub fn new_collection(&mut self, name: &str) -> &mut Collection {
        let collection = Collection::new(name);
        self.collections.push(collection);
        self.collections.last_mut().unwrap()
    }

    /// Get a collection by name
    pub fn get_collection(&self, name: &str) -> Option<&Collection> {
        self.collections.iter().find(|c| c.name == name)
    }

    /// Get a mutable collection by name
    pub fn get_collection_mut(&mut self, name: &str) -> Option<&mut Collection> {
        self.collections.iter_mut().find(|c| c.name == name)
    }

    /// Remove a collection by name
    pub fn remove_collection(&mut self, name: &str) {
        self.collections.retain(|c| c.name != name);
    }

    /// Add an environment
    pub fn add_environment(&mut self, env: Environment) {
        self.environments.push(env);
    }

    /// Create and add a new environment
    pub fn new_environment(&mut self, name: &str) -> &mut Environment {
        let env = Environment::new(name);
        self.environments.push(env);
        self.environments.last_mut().unwrap()
    }

    /// Get an environment by name
    pub fn get_environment(&self, name: &str) -> Option<&Environment> {
        if name == "global" || name == "Global" {
            Some(&self.global)
        } else {
            self.environments.iter().find(|e| e.name == name)
        }
    }

    /// Get all request URLs in the project
    pub fn all_urls(&self) -> Vec<&str> {
        self.collections
            .iter()
            .flat_map(|c| c.all_requests())
            .map(|r| r.url.as_str())
            .collect()
    }
}
