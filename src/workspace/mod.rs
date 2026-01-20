//! Workspace and project management
//!
//! Handles collections, environments, sessions, and import/export.

mod collections;
mod environments;
mod project;
mod session;
pub mod import;

pub use collections::{Collection, CollectionItem};
pub use environments::Environment;
pub use project::Project;
pub use session::Session;

use anyhow::Result;
use std::path::PathBuf;

use crate::app::Config;

/// Workspace manager
pub struct Workspace {
    /// Current project
    project: Option<Project>,

    /// Available environments
    environments: Vec<Environment>,

    /// Active environment
    active_environment: Option<String>,

    /// Workspace directory
    workspace_dir: PathBuf,

    /// Session manager
    session: Session,
}

impl Workspace {
    /// Create a new workspace
    pub fn new(config: &Config) -> Result<Self> {
        let workspace_dir = config
            .general
            .workspace_dir
            .clone()
            .unwrap_or_else(|| Config::data_dir().unwrap_or_else(|_| PathBuf::from(".")));

        // Create default environments
        let mut local_env = Environment::new("Local");
        local_env.add_variable("base_url", "http://localhost:8080");
        local_env.add_variable("api_version", "v1");

        let mut dev_env = Environment::new("Development");
        dev_env.add_variable("base_url", "https://dev.example.com");
        dev_env.add_variable("api_version", "v1");

        let mut staging_env = Environment::new("Staging");
        staging_env.add_variable("base_url", "https://staging.example.com");
        staging_env.add_variable("api_version", "v1");

        let mut prod_env = Environment::new("Production");
        prod_env.add_variable("base_url", "https://api.example.com");
        prod_env.add_variable("api_version", "v1");
        prod_env.add_secret("api_key", "YOUR_API_KEY_HERE");

        Ok(Self {
            project: None,
            environments: vec![local_env, dev_env, staging_env, prod_env],
            active_environment: None,
            workspace_dir,
            session: Session::new(),
        })
    }

    /// Load a project from file
    pub fn load_project(&mut self, path: &PathBuf) -> Result<()> {
        let project = Project::load(path)?;
        self.project = Some(project);
        Ok(())
    }

    /// Create a new project
    pub fn new_project(&mut self, name: &str) -> Result<()> {
        let project = Project::new(name);
        self.project = Some(project);
        Ok(())
    }

    /// Save current project
    pub fn save_project(&self) -> Result<()> {
        if let Some(project) = &self.project {
            project.save()?;
        }
        Ok(())
    }

    /// Get current project
    pub fn project(&self) -> Option<&Project> {
        self.project.as_ref()
    }

    /// Get mutable project
    pub fn project_mut(&mut self) -> Option<&mut Project> {
        self.project.as_mut()
    }

    /// Add environment
    pub fn add_environment(&mut self, env: Environment) {
        self.environments.push(env);
    }

    /// Set active environment
    pub fn set_active_environment(&mut self, name: &str) -> Result<()> {
        if self.environments.iter().any(|e| e.name == name) {
            self.active_environment = Some(name.to_string());
            Ok(())
        } else {
            Err(anyhow::anyhow!("Environment not found: {}", name))
        }
    }

    /// Get active environment
    pub fn active_environment(&self) -> Option<&Environment> {
        self.active_environment
            .as_ref()
            .and_then(|name| self.environments.iter().find(|e| &e.name == name))
    }

    /// Get all environments
    pub fn environments(&self) -> &[Environment] {
        &self.environments
    }

    /// Get session
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// Get mutable session
    pub fn session_mut(&mut self) -> &mut Session {
        &mut self.session
    }

    /// Resolve variable value from active environment
    pub fn resolve_variable(&self, name: &str) -> Option<String> {
        self.active_environment()
            .and_then(|env| env.get(name))
    }
}
