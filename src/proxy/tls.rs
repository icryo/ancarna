//! TLS certificate handling for HTTPS interception

#![allow(dead_code)]

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use parking_lot::RwLock;

/// Certificate Authority for generating site certificates
pub struct CertificateAuthority {
    /// CA certificate
    ca_cert: Certificate,

    /// CA key pair
    ca_key: KeyPair,

    /// Cached site certificates
    cert_cache: Arc<RwLock<HashMap<String, (String, String)>>>,

    /// CA certificate PEM
    ca_cert_pem: String,
}

impl CertificateAuthority {
    /// Create a new CA
    pub fn new() -> Result<Self> {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Ancarna Proxy CA");
        dn.push(DnType::OrganizationName, "Ancarna Security");
        dn.push(DnType::CountryName, "US");
        params.distinguished_name = dn;

        let key_pair = KeyPair::generate()?;
        let ca_cert = params.self_signed(&key_pair)?;
        let ca_cert_pem = ca_cert.pem();

        Ok(Self {
            ca_cert,
            ca_key: key_pair,
            cert_cache: Arc::new(RwLock::new(HashMap::new())),
            ca_cert_pem,
        })
    }

    /// Load CA from files
    ///
    /// Note: Currently only loads the key pair and regenerates the CA.
    /// For persistent CA certs across restarts, use save_to_files after generation.
    pub fn from_files(cert_path: &PathBuf, key_path: &PathBuf) -> Result<Self> {
        let _cert_pem = fs::read_to_string(cert_path)
            .context("Failed to read CA certificate")?;
        let key_pem = fs::read_to_string(key_path)
            .context("Failed to read CA private key")?;

        let key_pair = KeyPair::from_pem(&key_pem)
            .context("Failed to parse CA private key")?;

        // Recreate CA params with the existing key
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Ancarna Proxy CA");
        dn.push(DnType::OrganizationName, "Ancarna Security");
        dn.push(DnType::CountryName, "US");
        params.distinguished_name = dn;

        let ca_cert = params.self_signed(&key_pair)?;
        let ca_cert_pem = ca_cert.pem();

        Ok(Self {
            ca_cert,
            ca_key: key_pair,
            cert_cache: Arc::new(RwLock::new(HashMap::new())),
            ca_cert_pem,
        })
    }

    /// Save CA to files
    pub fn save_to_files(&self, cert_path: &PathBuf, key_path: &PathBuf) -> Result<()> {
        fs::write(cert_path, self.ca_cert_pem.as_bytes())
            .context("Failed to write CA certificate")?;
        fs::write(key_path, self.ca_key.serialize_pem().as_bytes())
            .context("Failed to write CA private key")?;
        Ok(())
    }

    /// Get CA certificate PEM
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Install CA certificate to system/browser trust stores
    /// Returns a tuple of (success messages, error messages)
    pub fn install_ca_cert(&self, cert_path: &PathBuf) -> (Vec<String>, Vec<String>) {
        let mut successes = Vec::new();
        let mut errors = Vec::new();

        // Ensure parent directory exists and write cert file
        if let Some(parent) = cert_path.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                errors.push(format!("Failed to create cert directory: {}", e));
                return (successes, errors);
            }
        }
        if let Err(e) = fs::write(cert_path, self.ca_cert_pem.as_bytes()) {
            errors.push(format!("Failed to write cert file: {}", e));
            return (successes, errors);
        }
        successes.push(format!("CA cert saved to {}", cert_path.display()));

        // Try NSS database (Chrome/Chromium)
        let home = std::env::var("HOME").unwrap_or_default();
        let nss_db = format!("{}/.pki/nssdb", home);

        if std::path::Path::new(&nss_db).exists() {
            let output = std::process::Command::new("certutil")
                .args([
                    "-d", &format!("sql:{}", nss_db),
                    "-A",
                    "-t", "C,,",
                    "-n", "ancarna-proxy-ca",
                    "-i", &cert_path.to_string_lossy(),
                ])
                .output();

            match output {
                Ok(out) if out.status.success() => {
                    successes.push("Installed to NSS database (Chrome/Chromium)".to_string());
                }
                Ok(out) => {
                    let err = String::from_utf8_lossy(&out.stderr);
                    if !err.contains("already exists") {
                        errors.push(format!("NSS certutil failed: {}", err));
                    } else {
                        successes.push("Already in NSS database".to_string());
                    }
                }
                Err(e) => {
                    errors.push(format!("certutil not found (install libnss3-tools): {}", e));
                }
            }
        } else {
            errors.push(format!("NSS database not found at {}", nss_db));
        }

        // System-wide requires sudo - provide instructions
        successes.push("For system-wide: sudo cp ~/.ancarna/ca.crt /usr/local/share/ca-certificates/ancarna.crt && sudo update-ca-certificates".to_string());

        (successes, errors)
    }

    /// Generate a certificate for a domain
    pub fn generate_cert(&self, domain: &str) -> Result<(String, String)> {
        // Check cache first
        {
            let cache = self.cert_cache.read();
            if let Some((cert, key)) = cache.get(domain) {
                return Ok((cert.clone(), key.clone()));
            }
        }

        // Generate new certificate
        let mut params = CertificateParams::default();

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, domain);
        params.distinguished_name = dn;

        // Add subject alternative names
        params.subject_alt_names = vec![
            SanType::DnsName(domain.try_into()?),
        ];

        // If it looks like an IP, add IP SAN
        if let Ok(ip) = domain.parse::<std::net::IpAddr>() {
            params.subject_alt_names.push(SanType::IpAddress(ip));
        }

        // Generate key pair for this certificate
        let key_pair = KeyPair::generate()?;
        let cert = params.signed_by(&key_pair, &self.ca_cert, &self.ca_key)?;

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        // Cache the certificate
        {
            let mut cache = self.cert_cache.write();
            cache.insert(domain.to_string(), (cert_pem.clone(), key_pem.clone()));
        }

        Ok((cert_pem, key_pem))
    }

    /// Clear the certificate cache
    pub fn clear_cache(&self) {
        self.cert_cache.write().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ca_creation() {
        let ca = CertificateAuthority::new();
        assert!(ca.is_ok());
    }

    #[test]
    fn test_cert_generation() {
        let ca = CertificateAuthority::new().unwrap();
        let result = ca.generate_cert("example.com");
        assert!(result.is_ok());

        let (cert, key) = result.unwrap();
        assert!(cert.contains("BEGIN CERTIFICATE"));
        assert!(key.contains("BEGIN PRIVATE KEY"));
    }
}
