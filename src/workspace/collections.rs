//! Request collections

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::http::Request;

/// A collection of requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collection {
    /// Collection ID
    pub id: String,

    /// Collection name
    pub name: String,

    /// Description
    pub description: Option<String>,

    /// Items in the collection
    pub items: Vec<CollectionItem>,

    /// Collection-level variables
    pub variables: HashMap<String, String>,

    /// Collection-level auth
    pub auth: Option<crate::http::AuthConfig>,

    /// Pre-request script
    pub pre_script: Option<String>,

    /// Post-request script
    pub post_script: Option<String>,
}

/// An item in a collection (can be a request or folder)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum CollectionItem {
    Request(Box<RequestItem>),
    Folder(FolderItem),
}

/// A request item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestItem {
    /// Item ID
    pub id: String,

    /// Item name
    pub name: String,

    /// The request
    pub request: Request,
}

/// A folder containing other items
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderItem {
    /// Folder ID
    pub id: String,

    /// Folder name
    pub name: String,

    /// Items in the folder
    pub items: Vec<CollectionItem>,

    /// Description
    pub description: Option<String>,
}

impl Collection {
    /// Create a new collection
    pub fn new(name: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: None,
            items: Vec::new(),
            variables: HashMap::new(),
            auth: None,
            pre_script: None,
            post_script: None,
        }
    }

    /// Add a request to the collection
    pub fn add_request(&mut self, name: &str, request: Request) {
        self.items.push(CollectionItem::Request(Box::new(RequestItem {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            request,
        })));
    }

    /// Add a folder to the collection
    pub fn add_folder(&mut self, name: &str) -> &mut FolderItem {
        self.items.push(CollectionItem::Folder(FolderItem {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            items: Vec::new(),
            description: None,
        }));

        match self.items.last_mut() {
            Some(CollectionItem::Folder(f)) => f,
            _ => unreachable!(),
        }
    }

    /// Find a request by ID
    pub fn find_request(&self, id: &str) -> Option<&Request> {
        self.find_request_recursive(&self.items, id)
    }

    fn find_request_recursive<'a>(
        &'a self,
        items: &'a [CollectionItem],
        id: &str,
    ) -> Option<&'a Request> {
        for item in items {
            match item {
                CollectionItem::Request(r) if r.id == id => return Some(&r.request),
                CollectionItem::Folder(f) => {
                    if let Some(r) = self.find_request_recursive(&f.items, id) {
                        return Some(r);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Get all requests (flattened)
    pub fn all_requests(&self) -> Vec<&Request> {
        let mut requests = Vec::new();
        self.collect_requests_recursive(&self.items, &mut requests);
        requests
    }

    fn collect_requests_recursive<'a>(
        &'a self,
        items: &'a [CollectionItem],
        requests: &mut Vec<&'a Request>,
    ) {
        for item in items {
            match item {
                CollectionItem::Request(r) => requests.push(&r.request),
                CollectionItem::Folder(f) => {
                    self.collect_requests_recursive(&f.items, requests);
                }
            }
        }
    }
}

impl FolderItem {
    /// Add a request to this folder
    pub fn add_request(&mut self, name: &str, request: Request) {
        self.items.push(CollectionItem::Request(Box::new(RequestItem {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            request,
        })));
    }

    /// Add a subfolder
    pub fn add_folder(&mut self, name: &str) -> &mut FolderItem {
        self.items.push(CollectionItem::Folder(FolderItem {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            items: Vec::new(),
            description: None,
        }));

        match self.items.last_mut() {
            Some(CollectionItem::Folder(f)) => f,
            _ => unreachable!(),
        }
    }
}
