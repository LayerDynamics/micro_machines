//! Common object metadata shared by all MicroMachines resources. SPEC-1 §3.3.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::Error;

/// Maximum length of an RFC 1123 label (matches Kubernetes object-name limits).
const MAX_LABEL_LEN: usize = 63;

/// Kubernetes-style metadata attached to every resource (SPEC-1 §3.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectMeta {
    pub uid: Uuid,
    pub name: String,
    #[serde(default = "default_namespace")]
    pub namespace: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

fn default_namespace() -> String {
    "default".to_string()
}

/// Validate a single RFC 1123 label: 1–63 chars, lowercase alphanumerics and
/// hyphens, starting and ending with an alphanumeric. This is the rule applied
/// to resource `name`/`namespace` so they are safe as DNS labels and IDs.
fn validate_label(field: &'static str, value: &str) -> Result<(), Error> {
    let reject = |reason: &'static str| Error::InvalidName {
        field,
        value: value.to_string(),
        reason,
    };

    if value.is_empty() {
        return Err(reject("must not be empty"));
    }
    if value.len() > MAX_LABEL_LEN {
        return Err(reject("must be at most 63 characters"));
    }

    let is_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let bytes = value.as_bytes();
    if !is_alnum(bytes[0]) || !is_alnum(bytes[bytes.len() - 1]) {
        return Err(reject(
            "must start and end with a lowercase alphanumeric character",
        ));
    }
    if !bytes.iter().all(|&b| is_alnum(b) || b == b'-') {
        return Err(reject(
            "may only contain lowercase alphanumerics and hyphens",
        ));
    }
    Ok(())
}

impl ObjectMeta {
    /// Create metadata for a new object in a namespace, generating a fresh uid.
    /// `now` is injected (not read from the clock) so callers stay testable.
    pub fn new(name: impl Into<String>, namespace: impl Into<String>, now: OffsetDateTime) -> Self {
        Self {
            uid: Uuid::new_v4(),
            name: name.into(),
            namespace: namespace.into(),
            labels: BTreeMap::new(),
            annotations: BTreeMap::new(),
            created_at: now,
        }
    }

    /// Check that `name` and `namespace` are valid RFC 1123 labels. Consumers
    /// call this before admitting a resource so invalid identifiers never reach
    /// the store or the VMM (SPEC-1 §3.3, FR-7/FR-9).
    pub fn validate(&self) -> Result<(), Error> {
        validate_label("name", &self.name)?;
        validate_label("namespace", &self.namespace)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_meta_has_namespace_and_unique_uid() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let a = ObjectMeta::new("web", "team-a", now);
        let b = ObjectMeta::new("web", "team-a", now);
        assert_eq!(a.namespace, "team-a");
        assert_ne!(a.uid, b.uid, "each object gets a distinct uid");
    }

    #[test]
    fn namespace_defaults_when_absent_in_json() {
        let json = r#"{"uid":"00000000-0000-0000-0000-000000000000","name":"x","created_at":"1970-01-01T00:00:00Z"}"#;
        let m: ObjectMeta = serde_json::from_str(json).unwrap();
        assert_eq!(m.namespace, "default");
    }

    #[test]
    fn validate_accepts_dns_label_names() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let m = ObjectMeta::new("web-01", "team-a", now);
        assert_eq!(m.validate(), Ok(()));
    }

    #[test]
    fn validate_rejects_empty_name() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let m = ObjectMeta::new("", "default", now);
        let err = m.validate().unwrap_err();
        assert!(matches!(err, Error::InvalidName { field: "name", .. }));
    }

    #[test]
    fn validate_rejects_uppercase_and_bad_edges() {
        let now = OffsetDateTime::UNIX_EPOCH;
        assert!(ObjectMeta::new("Web", "default", now).validate().is_err());
        assert!(ObjectMeta::new("-web", "default", now).validate().is_err());
        assert!(ObjectMeta::new("web-", "default", now).validate().is_err());
    }

    #[test]
    fn validate_rejects_overlong_name() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let long = "a".repeat(MAX_LABEL_LEN + 1);
        let m = ObjectMeta::new(long, "default", now);
        assert!(m.validate().is_err());
    }

    #[test]
    fn validate_checks_namespace_too() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let m = ObjectMeta::new("web", "Bad_NS", now);
        let err = m.validate().unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidName {
                field: "namespace",
                ..
            }
        ));
    }
}
