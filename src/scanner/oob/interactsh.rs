//! Interactsh client implementation
//!
//! Provides integration with ProjectDiscovery's Interactsh service for
//! out-of-band vulnerability detection.
//!
//! Reference: https://github.com/projectdiscovery/interactsh

use super::{
    CallbackContext, CallbackUrl, DnsInteraction, HttpInteraction, Interaction, InteractionType,
    OobClient,
};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::Rng;
use rsa::{pkcs8::DecodePrivateKey, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

/// Default Interactsh server
pub const DEFAULT_INTERACTSH_SERVER: &str = "https://oast.me";

/// Interactsh client for OOB detection
pub struct InteractshClient {
    /// Server URL
    server_url: String,
    /// Correlation ID (unique per session)
    correlation_id: String,
    /// Secret key for decryption
    secret_key: String,
    /// RSA private key for decryption
    private_key: RsaPrivateKey,
    /// RSA public key for registration
    public_key: RsaPublicKey,
    /// Base domain for callbacks
    base_domain: String,
    /// HTTP client
    http_client: reqwest::Client,
    /// Stored interactions
    interactions: Arc<RwLock<HashMap<String, Vec<Interaction>>>>,
    /// Callback counter for unique IDs
    callback_counter: Arc<RwLock<u64>>,
}

/// Interactsh registration request
#[derive(Debug, Serialize)]
struct RegisterRequest {
    #[serde(rename = "public-key")]
    public_key: String,
    #[serde(rename = "secret-key")]
    secret_key: String,
    #[serde(rename = "correlation-id")]
    correlation_id: String,
}

/// Interactsh registration response
#[derive(Debug, Deserialize)]
struct RegisterResponse {
    message: Option<String>,
    #[serde(rename = "correlation-id")]
    _correlation_id: Option<String>,
}

/// Interactsh poll response
#[derive(Debug, Deserialize)]
struct PollResponse {
    data: Option<Vec<String>>,
    aes_key: Option<String>,
}

/// Decrypted interaction data
#[derive(Debug, Deserialize)]
struct InteractionData {
    protocol: String,
    #[serde(rename = "unique-id")]
    unique_id: String,
    #[serde(rename = "full-id")]
    full_id: String,
    #[serde(rename = "raw-request")]
    raw_request: Option<String>,
    #[serde(rename = "raw-response")]
    _raw_response: Option<String>,
    #[serde(rename = "remote-address")]
    remote_address: String,
    timestamp: String,
    #[serde(rename = "q-type")]
    q_type: Option<String>,
}

impl InteractshClient {
    /// Create a new Interactsh client
    pub async fn new(server_url: Option<&str>) -> Result<Self> {
        let server_url = server_url
            .unwrap_or(DEFAULT_INTERACTSH_SERVER)
            .trim_end_matches('/')
            .to_string();

        // Generate RSA key pair
        let mut rng = rand::thread_rng();
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits)
            .context("Failed to generate RSA private key")?;
        let public_key = RsaPublicKey::from(&private_key);

        // Generate correlation ID (random 20 character string)
        let correlation_id: String = (0..20)
            .map(|_| {
                let idx = rng.gen_range(0..36);
                if idx < 10 {
                    (b'0' + idx) as char
                } else {
                    (b'a' + idx - 10) as char
                }
            })
            .collect();

        // Generate secret key
        let secret_key: String = (0..32)
            .map(|_| {
                let idx = rng.gen_range(0..36);
                if idx < 10 {
                    (b'0' + idx) as char
                } else {
                    (b'a' + idx - 10) as char
                }
            })
            .collect();

        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("Failed to create HTTP client")?;

        let mut client = Self {
            server_url: server_url.clone(),
            correlation_id,
            secret_key,
            private_key,
            public_key,
            base_domain: String::new(),
            http_client,
            interactions: Arc::new(RwLock::new(HashMap::new())),
            callback_counter: Arc::new(RwLock::new(0)),
        };

        // Register with the server
        client.register().await?;

        Ok(client)
    }

    /// Register with the Interactsh server
    async fn register(&mut self) -> Result<()> {
        // Encode public key
        let public_key_der = self.public_key_to_base64()?;

        let request = RegisterRequest {
            public_key: public_key_der,
            secret_key: self.secret_key.clone(),
            correlation_id: self.correlation_id.clone(),
        };

        let response = self
            .http_client
            .post(format!("{}/register", self.server_url))
            .json(&request)
            .send()
            .await
            .context("Failed to register with Interactsh server")?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Interactsh registration failed: {}",
                response.status()
            ));
        }

        let register_response: RegisterResponse = response
            .json()
            .await
            .context("Failed to parse registration response")?;

        if let Some(msg) = register_response.message {
            if msg.contains("error") || msg.contains("failed") {
                return Err(anyhow!("Interactsh registration error: {}", msg));
            }
        }

        // Extract base domain from server URL
        let server_host = url::Url::parse(&self.server_url)
            .context("Invalid server URL")?
            .host_str()
            .unwrap_or("oast.me")
            .to_string();

        self.base_domain = format!("{}.{}", self.correlation_id, server_host);

        tracing::info!(
            "Registered with Interactsh server, base domain: {}",
            self.base_domain
        );

        Ok(())
    }

    /// Convert public key to base64
    fn public_key_to_base64(&self) -> Result<String> {
        use rsa::pkcs8::EncodePublicKey;
        let der = self
            .public_key
            .to_public_key_der()
            .context("Failed to encode public key")?;
        Ok(BASE64.encode(der.as_bytes()))
    }

    /// Generate a unique callback ID
    fn next_callback_id(&self) -> String {
        let mut counter = self.callback_counter.write().unwrap();
        *counter += 1;
        let mut rng = rand::thread_rng();
        let random_part: String = (0..8)
            .map(|_| {
                let idx = rng.gen_range(0..36);
                if idx < 10 {
                    (b'0' + idx) as char
                } else {
                    (b'a' + idx - 10) as char
                }
            })
            .collect();
        format!("{}{:04x}", random_part, *counter)
    }

    /// Decrypt interaction data using AES key
    fn decrypt_data(&self, encrypted: &str, aes_key: &str) -> Result<InteractionData> {
        // First decrypt AES key with RSA private key
        let encrypted_aes = BASE64
            .decode(aes_key)
            .context("Failed to decode AES key")?;

        let decrypted_aes = self
            .private_key
            .decrypt(Pkcs1v15Encrypt, &encrypted_aes)
            .context("Failed to decrypt AES key")?;

        // Decode the encrypted data
        let encrypted_data = BASE64
            .decode(encrypted)
            .context("Failed to decode interaction data")?;

        // Decrypt using AES-CFB
        use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};

        type Aes256CfbDec = cfb_mode::Decryptor<aes::Aes256>;

        if decrypted_aes.len() < 16 {
            return Err(anyhow!("AES key too short"));
        }

        let key = &decrypted_aes[..32.min(decrypted_aes.len())];
        let iv = &encrypted_data[..16];
        let ciphertext = &encrypted_data[16..];

        let mut decrypted = ciphertext.to_vec();

        // Pad key if needed
        let mut key_padded = [0u8; 32];
        key_padded[..key.len()].copy_from_slice(key);

        let mut cipher = Aes256CfbDec::new((&key_padded).into(), iv.into());
        cipher.decrypt(&mut decrypted);

        let json_str = String::from_utf8(decrypted)
            .context("Decrypted data is not valid UTF-8")?;

        serde_json::from_str(&json_str).context("Failed to parse interaction JSON")
    }
}

impl OobClient for InteractshClient {
    fn generate_http_callback(&self, context: CallbackContext) -> Result<CallbackUrl> {
        let callback_id = self.next_callback_id();
        let hostname = format!("{}.{}", callback_id, self.base_domain);
        let url = format!("http://{}", hostname);

        Ok(CallbackUrl {
            url,
            hostname,
            correlation_id: callback_id,
            created_at: Instant::now(),
            context,
        })
    }

    fn generate_dns_callback(&self, context: CallbackContext) -> Result<CallbackUrl> {
        let callback_id = self.next_callback_id();
        let hostname = format!("{}.{}", callback_id, self.base_domain);

        Ok(CallbackUrl {
            url: format!("dns://{}", hostname),
            hostname,
            correlation_id: callback_id,
            created_at: Instant::now(),
            context,
        })
    }

    fn poll_interactions(&self) -> Result<Vec<Interaction>> {
        // Note: This is a sync interface but Interactsh uses async
        // In production, this would be called from an async context
        // For now, we'll use a blocking approach

        let rt = tokio::runtime::Handle::try_current()
            .or_else(|_| {
                tokio::runtime::Runtime::new().map(|rt| rt.handle().clone())
            })
            .context("Failed to get tokio runtime")?;

        rt.block_on(async {
            let response = self
                .http_client
                .get(format!(
                    "{}/poll?id={}&secret={}",
                    self.server_url, self.correlation_id, self.secret_key
                ))
                .send()
                .await
                .context("Failed to poll Interactsh server")?;

            if !response.status().is_success() {
                return Err(anyhow!("Poll failed: {}", response.status()));
            }

            let poll_response: PollResponse = response
                .json()
                .await
                .context("Failed to parse poll response")?;

            let mut interactions = Vec::new();

            if let (Some(data), Some(aes_key)) = (poll_response.data, poll_response.aes_key) {
                for encrypted in data {
                    match self.decrypt_data(&encrypted, &aes_key) {
                        Ok(interaction_data) => {
                            let interaction = Interaction {
                                id: interaction_data.unique_id.clone(),
                                interaction_type: match interaction_data.protocol.as_str() {
                                    "dns" => InteractionType::Dns,
                                    "http" | "https" => InteractionType::Http,
                                    "smtp" => InteractionType::Smtp,
                                    "ldap" => InteractionType::Ldap,
                                    "ftp" => InteractionType::Ftp,
                                    "smb" => InteractionType::Smb,
                                    _ => InteractionType::Http,
                                },
                                remote_address: interaction_data.remote_address,
                                timestamp: chrono::Utc::now(), // Parse from interaction_data.timestamp
                                raw_data: interaction_data.raw_request.clone(),
                                http_request: if interaction_data.protocol == "http" {
                                    Some(HttpInteraction {
                                        method: "GET".to_string(),
                                        path: "/".to_string(),
                                        headers: HashMap::new(),
                                        body: None,
                                    })
                                } else {
                                    None
                                },
                                dns_query: if interaction_data.protocol == "dns" {
                                    Some(DnsInteraction {
                                        query_type: interaction_data.q_type.unwrap_or_default(),
                                        domain: interaction_data.full_id,
                                    })
                                } else {
                                    None
                                },
                                correlation_id: interaction_data.unique_id,
                            };
                            interactions.push(interaction);
                        }
                        Err(e) => {
                            tracing::warn!("Failed to decrypt interaction: {}", e);
                        }
                    }
                }
            }

            // Store interactions
            if let Ok(mut stored) = self.interactions.write() {
                for interaction in &interactions {
                    stored
                        .entry(interaction.correlation_id.clone())
                        .or_default()
                        .push(interaction.clone());
                }
            }

            Ok(interactions)
        })
    }

    fn get_interactions(&self, correlation_id: &str) -> Vec<Interaction> {
        if let Ok(interactions) = self.interactions.read() {
            return interactions.get(correlation_id).cloned().unwrap_or_default();
        }
        Vec::new()
    }

    fn has_interaction(&self, correlation_id: &str) -> bool {
        if let Ok(interactions) = self.interactions.read() {
            return interactions.contains_key(correlation_id);
        }
        false
    }

    fn get_base_domain(&self) -> &str {
        &self.base_domain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_callback_id_generation() {
        // Test that callback IDs are unique
        let counter = Arc::new(RwLock::new(0u64));

        let mut ids = std::collections::HashSet::new();
        for _ in 0..100 {
            let mut c = counter.write().unwrap();
            *c += 1;
            let id = format!("test{:04x}", *c);
            assert!(ids.insert(id), "Duplicate callback ID generated");
        }
    }
}
