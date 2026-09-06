// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2025-2026 Dendri contributors

//! Transactional email via Alibaba Cloud DirectMail (SingleSendMail).
//!
//! Signs the RPC request (v1.0, HMAC-SHA1) by hand rather than pulling an SDK —
//! the server already has reqwest + hmac + sha1 + base64 + uuid. Sends from a
//! DirectMail-scoped RAM key so a server compromise can't touch the rest of the
//! Alibaba account.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use reqwest::Client;
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

#[derive(Clone)]
pub struct Mailer {
    access_key_id: String,
    access_key_secret: String,
    region: String,
    from: String,
    from_alias: String,
    http: Client,
}

impl Mailer {
    pub fn new(
        access_key_id: String,
        access_key_secret: String,
        region: String,
        from: String,
    ) -> Self {
        Self {
            access_key_id,
            access_key_secret,
            region,
            from,
            from_alias: "Dendri".to_string(),
            http: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Send an HTML email. Returns Err(reason) on failure.
    pub async fn send(&self, to: &str, subject: &str, html: &str) -> Result<(), String> {
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let ts = iso8601_utc(SystemTime::now());

        // All request params (common + action). Signed set = these exactly.
        let mut params: Vec<(String, String)> = vec![
            ("Format".into(), "JSON".into()),
            ("Version".into(), "2015-11-23".into()),
            ("AccessKeyId".into(), self.access_key_id.clone()),
            ("SignatureMethod".into(), "HMAC-SHA1".into()),
            ("SignatureVersion".into(), "1.0".into()),
            ("SignatureNonce".into(), nonce),
            ("Timestamp".into(), ts),
            ("RegionId".into(), self.region.clone()),
            ("Action".into(), "SingleSendMail".into()),
            ("AccountName".into(), self.from.clone()),
            ("AddressType".into(), "1".into()),
            ("ReplyToAddress".into(), "false".into()),
            ("FromAlias".into(), self.from_alias.clone()),
            ("ToAddress".into(), to.to_string()),
            ("Subject".into(), subject.to_string()),
            ("HtmlBody".into(), html.to_string()),
        ];

        let signature = self.sign("POST", &mut params);
        params.push(("Signature".into(), signature));

        let endpoint = format!("https://dm.{}.aliyuncs.com/", self.region);
        let resp = self
            .http
            .post(&endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| format!("directmail request failed: {e}"))?;

        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(format!("directmail {status}: {body}"))
        }
    }

    /// Compute the RPC signature. Sorts params, builds the canonicalized query
    /// string, and HMAC-SHA1s the string-to-sign with `secret + "&"`.
    fn sign(&self, method: &str, params: &mut [(String, String)]) -> String {
        params.sort_by(|a, b| a.0.cmp(&b.0));
        let canonical = params
            .iter()
            .map(|(k, v)| format!("{}={}", rfc3986(k), rfc3986(v)))
            .collect::<Vec<_>>()
            .join("&");
        let string_to_sign = format!("{}&{}&{}", method, rfc3986("/"), rfc3986(&canonical));

        let mut mac = HmacSha1::new_from_slice(format!("{}&", self.access_key_secret).as_bytes())
            .expect("HMAC accepts any key length");
        mac.update(string_to_sign.as_bytes());
        base64_std(&mac.finalize().into_bytes())
    }
}

/// RFC3986 percent-encoding as Alibaba's RPC signing requires: encode
/// everything except `A-Za-z0-9-_.~`.
fn rfc3986(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        }
    }
    out
}

fn base64_std(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Format a SystemTime as `YYYY-MM-DDTHH:MM:SSZ` (UTC), which the RPC API
/// requires for the Timestamp param. Dependency-free (Howard Hinnant's
/// days→civil algorithm) since we have no date crate.
fn iso8601_utc(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3986_encodes_per_alibaba_rules() {
        assert_eq!(rfc3986("a b"), "a%20b");
        assert_eq!(rfc3986("a@b.com"), "a%40b.com");
        assert_eq!(rfc3986("~-_.AZaz09"), "~-_.AZaz09"); // unreserved untouched
        assert_eq!(rfc3986("/"), "%2F");
        assert_eq!(rfc3986("v=spf1"), "v%3Dspf1");
    }

    #[test]
    fn iso8601_known_epoch() {
        // 2021-01-01T00:00:00Z = 1609459200
        assert_eq!(
            iso8601_utc(UNIX_EPOCH + std::time::Duration::from_secs(1609459200)),
            "2021-01-01T00:00:00Z"
        );
        // 1970-01-01T00:00:00Z
        assert_eq!(iso8601_utc(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        // A leap-year date: 2024-02-29T12:34:56Z = 1709210096
        assert_eq!(
            iso8601_utc(UNIX_EPOCH + std::time::Duration::from_secs(1709210096)),
            "2024-02-29T12:34:56Z"
        );
    }

    #[test]
    fn signature_is_stable_and_base64() {
        let m = Mailer::new(
            "testid".into(),
            "testsecret".into(),
            "ap-southeast-1".into(),
            "noreply@dendri.dev".into(),
        );
        let mut p = vec![
            ("Action".to_string(), "SingleSendMail".to_string()),
            ("ToAddress".to_string(), "x@y.com".to_string()),
        ];
        let sig = m.sign("POST", &mut p);
        assert!(!sig.is_empty());
        // deterministic for the same input
        let mut p2 = vec![
            ("ToAddress".to_string(), "x@y.com".to_string()),
            ("Action".to_string(), "SingleSendMail".to_string()),
        ];
        assert_eq!(sig, m.sign("POST", &mut p2)); // order-independent (sorted)
    }
}
