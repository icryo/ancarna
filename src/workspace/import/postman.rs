//! Postman collection import

use anyhow::{Context, Result};
use serde::Deserialize;

use super::ImportResult;
use crate::http::{AuthConfig, Request};
use crate::workspace::collections::{Collection, CollectionItem, FolderItem, RequestItem};

/// Import a Postman collection
pub fn import(content: &str) -> Result<ImportResult> {
    let postman: PostmanCollection = serde_json::from_str(content)
        .context("Failed to parse Postman collection")?;

    let collection = convert_collection(&postman)?;
    Ok(ImportResult::Collection(collection))
}

fn convert_collection(postman: &PostmanCollection) -> Result<Collection> {
    let mut collection = Collection::new(&postman.info.name);
    collection.description = postman.info.description.clone();

    // Convert items
    for item in &postman.item {
        collection.items.push(convert_item(item)?);
    }

    // Convert variables
    if let Some(vars) = &postman.variable {
        for var in vars {
            if let (Some(key), Some(value)) = (&var.key, &var.value) {
                collection.variables.insert(key.clone(), value.clone());
            }
        }
    }

    Ok(collection)
}

fn convert_item(item: &PostmanItem) -> Result<CollectionItem> {
    if let Some(items) = &item.item {
        // This is a folder
        let mut folder = FolderItem {
            id: uuid::Uuid::new_v4().to_string(),
            name: item.name.clone(),
            items: Vec::new(),
            description: item.description.clone(),
        };

        for child in items {
            folder.items.push(convert_item(child)?);
        }

        Ok(CollectionItem::Folder(folder))
    } else if let Some(request) = &item.request {
        // This is a request
        let mut req = Request::new(
            &request.method,
            &get_url_string(&request.url),
        );
        req.name = item.name.clone();

        // Convert headers
        if let Some(headers) = &request.header {
            for header in headers {
                if header.disabled != Some(true) {
                    req.headers.insert(header.key.clone(), header.value.clone());
                }
            }
        }

        // Convert body
        if let Some(body) = &request.body {
            if let Some(raw) = &body.raw {
                req.body = Some(raw.clone());
            }
        }

        // Convert auth
        if let Some(auth) = &request.auth {
            req.auth = convert_auth(auth);
        }

        Ok(CollectionItem::Request(Box::new(RequestItem {
            id: uuid::Uuid::new_v4().to_string(),
            name: item.name.clone(),
            request: req,
        })))
    } else {
        Err(anyhow::anyhow!("Invalid item: neither folder nor request"))
    }
}

fn get_url_string(url: &PostmanUrl) -> String {
    match url {
        PostmanUrl::String(s) => s.clone(),
        PostmanUrl::Object { raw, .. } => raw.clone().unwrap_or_default(),
    }
}

fn convert_auth(auth: &PostmanAuth) -> Option<AuthConfig> {
    match auth.type_.as_str() {
        "basic" => {
            let username = auth
                .basic
                .as_ref()?
                .iter()
                .find(|v| v.key == "username")?
                .value
                .clone();
            let password = auth
                .basic
                .as_ref()?
                .iter()
                .find(|v| v.key == "password")?
                .value
                .clone();
            Some(AuthConfig::Basic { username, password })
        }
        "bearer" => {
            let token = auth
                .bearer
                .as_ref()?
                .iter()
                .find(|v| v.key == "token")?
                .value
                .clone();
            Some(AuthConfig::Bearer { token })
        }
        _ => None,
    }
}

// Postman collection structures

#[derive(Debug, Deserialize)]
struct PostmanCollection {
    info: PostmanInfo,
    item: Vec<PostmanItem>,
    variable: Option<Vec<PostmanVariable>>,
}

#[derive(Debug, Deserialize)]
struct PostmanInfo {
    name: String,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PostmanItem {
    name: String,
    description: Option<String>,
    item: Option<Vec<PostmanItem>>,
    request: Option<PostmanRequest>,
}

#[derive(Debug, Deserialize)]
struct PostmanRequest {
    method: String,
    url: PostmanUrl,
    header: Option<Vec<PostmanHeader>>,
    body: Option<PostmanBody>,
    auth: Option<PostmanAuth>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PostmanUrl {
    String(String),
    Object {
        raw: Option<String>,
        host: Option<Vec<String>>,
        path: Option<Vec<String>>,
    },
}

#[derive(Debug, Deserialize)]
struct PostmanHeader {
    key: String,
    value: String,
    disabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct PostmanBody {
    mode: Option<String>,
    raw: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PostmanAuth {
    #[serde(rename = "type")]
    type_: String,
    basic: Option<Vec<PostmanAuthValue>>,
    bearer: Option<Vec<PostmanAuthValue>>,
}

#[derive(Debug, Deserialize)]
struct PostmanAuthValue {
    key: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct PostmanVariable {
    key: Option<String>,
    value: Option<String>,
}
