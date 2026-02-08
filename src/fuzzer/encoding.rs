//! Payload encoding support for fuzzing
//!
//! Provides various encoding transformations to bypass WAFs and filters.

use std::fmt;

/// Payload encoding types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PayloadEncoding {
    /// No encoding - raw payload
    #[default]
    None,
    /// URL encoding (percent encoding)
    UrlEncode,
    /// Double URL encoding
    DoubleUrlEncode,
    /// Base64 encoding
    Base64,
    /// HTML entity encoding
    HtmlEntity,
    /// HTML entity encoding (decimal)
    HtmlEntityDecimal,
    /// JavaScript Unicode escape
    JavaScriptUnicode,
    /// JavaScript hex escape
    JavaScriptHex,
    /// Hex encoding
    Hex,
    /// Unicode encoding (\uXXXX)
    Unicode,
    /// ASCII hex encoding
    AsciiHex,
}

impl PayloadEncoding {
    /// Get all encoding types
    pub fn all() -> &'static [PayloadEncoding] {
        &[
            PayloadEncoding::None,
            PayloadEncoding::UrlEncode,
            PayloadEncoding::DoubleUrlEncode,
            PayloadEncoding::Base64,
            PayloadEncoding::HtmlEntity,
            PayloadEncoding::HtmlEntityDecimal,
            PayloadEncoding::JavaScriptUnicode,
            PayloadEncoding::JavaScriptHex,
            PayloadEncoding::Hex,
            PayloadEncoding::Unicode,
            PayloadEncoding::AsciiHex,
        ]
    }

    /// Get the display name
    pub fn name(&self) -> &'static str {
        match self {
            PayloadEncoding::None => "None",
            PayloadEncoding::UrlEncode => "URL Encode",
            PayloadEncoding::DoubleUrlEncode => "Double URL Encode",
            PayloadEncoding::Base64 => "Base64",
            PayloadEncoding::HtmlEntity => "HTML Entity",
            PayloadEncoding::HtmlEntityDecimal => "HTML Entity (Decimal)",
            PayloadEncoding::JavaScriptUnicode => "JavaScript Unicode",
            PayloadEncoding::JavaScriptHex => "JavaScript Hex",
            PayloadEncoding::Hex => "Hex",
            PayloadEncoding::Unicode => "Unicode (\\uXXXX)",
            PayloadEncoding::AsciiHex => "ASCII Hex",
        }
    }

    /// Get short name for display
    pub fn short_name(&self) -> &'static str {
        match self {
            PayloadEncoding::None => "none",
            PayloadEncoding::UrlEncode => "url",
            PayloadEncoding::DoubleUrlEncode => "url2",
            PayloadEncoding::Base64 => "b64",
            PayloadEncoding::HtmlEntity => "html",
            PayloadEncoding::HtmlEntityDecimal => "htmld",
            PayloadEncoding::JavaScriptUnicode => "jsu",
            PayloadEncoding::JavaScriptHex => "jsx",
            PayloadEncoding::Hex => "hex",
            PayloadEncoding::Unicode => "uni",
            PayloadEncoding::AsciiHex => "ahex",
        }
    }

    /// Encode a payload using this encoding type
    pub fn encode(&self, payload: &str) -> String {
        match self {
            PayloadEncoding::None => payload.to_string(),
            PayloadEncoding::UrlEncode => url_encode(payload),
            PayloadEncoding::DoubleUrlEncode => url_encode(&url_encode(payload)),
            PayloadEncoding::Base64 => base64_encode(payload),
            PayloadEncoding::HtmlEntity => html_entity_encode(payload),
            PayloadEncoding::HtmlEntityDecimal => html_entity_decimal_encode(payload),
            PayloadEncoding::JavaScriptUnicode => javascript_unicode_encode(payload),
            PayloadEncoding::JavaScriptHex => javascript_hex_encode(payload),
            PayloadEncoding::Hex => hex_encode(payload),
            PayloadEncoding::Unicode => unicode_encode(payload),
            PayloadEncoding::AsciiHex => ascii_hex_encode(payload),
        }
    }

    /// Cycle to next encoding
    pub fn next(&self) -> Self {
        let all = Self::all();
        let idx = all.iter().position(|e| e == self).unwrap_or(0);
        all[(idx + 1) % all.len()]
    }

    /// Cycle to previous encoding
    pub fn prev(&self) -> Self {
        let all = Self::all();
        let idx = all.iter().position(|e| e == self).unwrap_or(0);
        if idx == 0 {
            all[all.len() - 1]
        } else {
            all[idx - 1]
        }
    }
}

impl fmt::Display for PayloadEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// URL encode (percent encoding) a string
pub fn url_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len() * 3);
    for byte in input.bytes() {
        match byte {
            // Unreserved characters (RFC 3986)
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            // Everything else gets percent-encoded
            _ => {
                encoded.push('%');
                encoded.push_str(&format!("{:02X}", byte));
            }
        }
    }
    encoded
}

/// URL encode all characters (aggressive encoding for WAF bypass)
pub fn url_encode_all(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len() * 3);
    for byte in input.bytes() {
        encoded.push('%');
        encoded.push_str(&format!("{:02X}", byte));
    }
    encoded
}

/// Base64 encode a string
pub fn base64_encode(input: &str) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    STANDARD.encode(input.as_bytes())
}

/// HTML entity encode (named entities for special chars, hex for others)
pub fn html_entity_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len() * 6);
    for ch in input.chars() {
        match ch {
            '<' => encoded.push_str("&lt;"),
            '>' => encoded.push_str("&gt;"),
            '&' => encoded.push_str("&amp;"),
            '"' => encoded.push_str("&quot;"),
            '\'' => encoded.push_str("&#x27;"),
            '/' => encoded.push_str("&#x2F;"),
            // Encode other non-alphanumeric as hex entities
            _ if !ch.is_alphanumeric() && !ch.is_whitespace() => {
                encoded.push_str(&format!("&#x{:X};", ch as u32));
            }
            _ => encoded.push(ch),
        }
    }
    encoded
}

/// HTML entity encode using decimal entities
pub fn html_entity_decimal_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len() * 8);
    for ch in input.chars() {
        if ch.is_alphanumeric() {
            encoded.push(ch);
        } else {
            encoded.push_str(&format!("&#{};", ch as u32));
        }
    }
    encoded
}

/// JavaScript Unicode escape (\uXXXX)
pub fn javascript_unicode_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len() * 6);
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            encoded.push(ch);
        } else {
            encoded.push_str(&format!("\\u{:04X}", ch as u32));
        }
    }
    encoded
}

/// JavaScript hex escape (\xXX)
pub fn javascript_hex_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len() * 4);
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("\\x{:02X}", byte));
        }
    }
    encoded
}

/// Hex encode (0xXX format)
pub fn hex_encode(input: &str) -> String {
    input
        .bytes()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

/// Unicode encode (\uXXXX for all chars)
pub fn unicode_encode(input: &str) -> String {
    input
        .chars()
        .map(|ch| format!("\\u{:04X}", ch as u32))
        .collect()
}

/// ASCII hex encode (\\xXX for all bytes)
pub fn ascii_hex_encode(input: &str) -> String {
    input
        .bytes()
        .map(|b| format!("\\x{:02X}", b))
        .collect()
}

/// Payload processor for chaining transformations
#[derive(Debug, Clone, Default)]
pub struct PayloadProcessor {
    /// Prefix to add before payload
    pub prefix: Option<String>,
    /// Suffix to add after payload
    pub suffix: Option<String>,
    /// Encoding to apply
    pub encoding: PayloadEncoding,
    /// Whether to encode prefix/suffix too
    pub encode_wrapper: bool,
}

impl PayloadProcessor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_encoding(mut self, encoding: PayloadEncoding) -> Self {
        self.encoding = encoding;
        self
    }

    pub fn with_prefix(mut self, prefix: &str) -> Self {
        self.prefix = Some(prefix.to_string());
        self
    }

    pub fn with_suffix(mut self, suffix: &str) -> Self {
        self.suffix = Some(suffix.to_string());
        self
    }

    pub fn encode_wrapper(mut self, encode: bool) -> Self {
        self.encode_wrapper = encode;
        self
    }

    /// Process a payload through all transformations
    pub fn process(&self, payload: &str) -> String {
        let encoded = self.encoding.encode(payload);

        let prefix = self.prefix.as_deref().unwrap_or("");
        let suffix = self.suffix.as_deref().unwrap_or("");

        if self.encode_wrapper {
            format!(
                "{}{}{}",
                self.encoding.encode(prefix),
                encoded,
                self.encoding.encode(suffix)
            )
        } else {
            format!("{}{}{}", prefix, encoded, suffix)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_encode() {
        assert_eq!(url_encode("test"), "test");
        assert_eq!(url_encode("<script>"), "%3Cscript%3E");
        assert_eq!(url_encode("a b"), "a%20b");
        assert_eq!(url_encode("'\""), "%27%22");
    }

    #[test]
    fn test_double_url_encode() {
        let single = url_encode("<");
        assert_eq!(single, "%3C");
        let double = url_encode(&single);
        assert_eq!(double, "%253C");
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode("test"), "dGVzdA==");
        assert_eq!(base64_encode("<script>alert(1)</script>"), "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==");
    }

    #[test]
    fn test_html_entity_encode() {
        assert_eq!(html_entity_encode("<"), "&lt;");
        assert_eq!(html_entity_encode(">"), "&gt;");
        assert_eq!(html_entity_encode("&"), "&amp;");
        assert_eq!(html_entity_encode("\""), "&quot;");
    }

    #[test]
    fn test_javascript_unicode_encode() {
        assert_eq!(javascript_unicode_encode("a"), "a");
        assert_eq!(javascript_unicode_encode("<"), "\\u003C");
        assert_eq!(javascript_unicode_encode("'"), "\\u0027");
    }

    #[test]
    fn test_javascript_hex_encode() {
        assert_eq!(javascript_hex_encode("a"), "a");
        assert_eq!(javascript_hex_encode("<"), "\\x3C");
    }

    #[test]
    fn test_payload_processor() {
        let processor = PayloadProcessor::new()
            .with_encoding(PayloadEncoding::UrlEncode)
            .with_prefix("test=")
            .with_suffix("&done");

        assert_eq!(processor.process("<script>"), "test=%3Cscript%3E&done");
    }

    #[test]
    fn test_encoding_cycle() {
        let enc = PayloadEncoding::None;
        assert_eq!(enc.next(), PayloadEncoding::UrlEncode);
        assert_eq!(PayloadEncoding::AsciiHex.next(), PayloadEncoding::None);
    }
}
