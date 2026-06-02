//! Authentication claims + namespace-scoped RBAC (SPEC-1 FR-29, FR-30).
//!
//! Two pure concerns the REST layer (Task 6) composes:
//!
//! 1. **Identity** — [`Claims`] is the shape of the OIDC/JWT we accept; the
//!    middleware verifies the token signature with the provider's key (jsonwebtoken)
//!    and then trusts these claims. [`Claims::is_expired`] is the time check, with
//!    `now` injected so it is deterministic in tests.
//! 2. **Authorization** — [`authorize`] decides whether a subject's role binding in
//!    a namespace permits a verb. A subject with no binding in the target namespace
//!    is denied, which is what enforces namespace isolation (FR-30).
//!
//! Both are IO-free, so the policy is exhaustively unit-testable and lives in one
//! place rather than smeared across handlers.
use mm_api_types::Error;
use serde::{Deserialize, Serialize};

/// A role a subject can hold in a namespace, ordered by privilege so a simple
/// `>=` comparison answers "is this role at least as powerful as required".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Viewer,
    Operator,
    Admin,
}

impl Role {
    /// The canonical wire/DB name (the `rbac_bindings.role` TEXT column).
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Operator => "operator",
            Role::Admin => "admin",
        }
    }

    /// Parse a role name from the database / API, rejecting anything unknown so a
    /// typo never silently grants or drops access.
    pub fn parse(s: &str) -> Result<Role, Error> {
        match s {
            "viewer" => Ok(Role::Viewer),
            "operator" => Ok(Role::Operator),
            "admin" => Ok(Role::Admin),
            other => Err(Error::UnknownState(format!("role:{other}"))),
        }
    }
}

/// An action a request wants to perform on a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Get,
    List,
    Create,
    Update,
    Delete,
    /// Run a command inside a running machine's guest (cluster exec, FR-13). An
    /// operator-level action: it mutates guest state but does not create or destroy
    /// the machine resource itself.
    Exec,
}

/// The minimum role required for a verb. Reads (Get/List) need a viewer; mutations
/// (Create/Update) and exec need an operator; destruction (Delete) needs an admin.
fn required(verb: Verb) -> Role {
    match verb {
        Verb::Get | Verb::List => Role::Viewer,
        Verb::Create | Verb::Update | Verb::Exec => Role::Operator,
        Verb::Delete => Role::Admin,
    }
}

/// Authorize `verb` in `namespace` given the subject's role binding.
///
/// `binding` is the `(namespace, role)` the subject holds, as looked up from
/// `rbac_bindings` by the JWT `sub`. Access is granted only when the binding is for
/// the *same* namespace and the role meets the verb's requirement; any other case —
/// including a binding in a different namespace — is denied, enforcing namespace
/// isolation (FR-30).
pub fn authorize(binding: Option<(&str, Role)>, namespace: &str, verb: Verb) -> bool {
    match binding {
        Some((ns, role)) if ns == namespace => role >= required(verb),
        _ => false,
    }
}

/// The subset of OIDC/JWT claims the control plane relies on. The middleware
/// validates the signature, then `sub` identifies the caller for RBAC lookup and
/// audit, and `exp` bounds the token's lifetime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject — the stable user/service identifier (RBAC key, audit actor).
    pub sub: String,
    /// Issuer — the OIDC provider URL.
    pub iss: String,
    /// Audience — who the token is for (this control plane).
    #[serde(default)]
    pub aud: String,
    /// Expiry, as a Unix timestamp in seconds.
    pub exp: i64,
}

impl Claims {
    /// True if the token is expired at `now_unix` (seconds since the epoch).
    pub fn is_expired(&self, now_unix: i64) -> bool {
        self.exp <= now_unix
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn viewer_can_list_not_create() {
        assert!(authorize(
            Some(("team-a", Role::Viewer)),
            "team-a",
            Verb::List
        ));
        assert!(!authorize(
            Some(("team-a", Role::Viewer)),
            "team-a",
            Verb::Create
        ));
    }

    #[test]
    fn operator_can_create_not_delete() {
        assert!(authorize(
            Some(("team-a", Role::Operator)),
            "team-a",
            Verb::Create
        ));
        assert!(!authorize(
            Some(("team-a", Role::Operator)),
            "team-a",
            Verb::Delete
        ));
    }

    #[test]
    fn operator_can_exec_viewer_cannot() {
        // Exec runs a command in the guest — an operator action, denied to viewers.
        assert!(authorize(
            Some(("team-a", Role::Operator)),
            "team-a",
            Verb::Exec
        ));
        assert!(!authorize(
            Some(("team-a", Role::Viewer)),
            "team-a",
            Verb::Exec
        ));
    }

    #[test]
    fn admin_can_delete() {
        assert!(authorize(
            Some(("team-a", Role::Admin)),
            "team-a",
            Verb::Delete
        ));
    }

    #[test]
    fn cross_namespace_is_denied() {
        // Even an admin in team-a has no access to team-b (FR-30 isolation).
        assert!(!authorize(
            Some(("team-a", Role::Admin)),
            "team-b",
            Verb::Get
        ));
    }

    #[test]
    fn no_binding_is_denied() {
        assert!(!authorize(None, "team-a", Verb::Get));
    }

    #[test]
    fn role_parse_roundtrips_and_rejects_unknown() {
        for r in [Role::Viewer, Role::Operator, Role::Admin] {
            assert_eq!(Role::parse(r.as_str()).unwrap(), r);
        }
        assert!(Role::parse("superuser").is_err());
    }

    #[test]
    fn expiry_is_checked_against_now() {
        let c = Claims {
            sub: "alice".into(),
            iss: "https://issuer".into(),
            aud: "mm".into(),
            exp: 1000,
        };
        assert!(!c.is_expired(999));
        assert!(c.is_expired(1000));
        assert!(c.is_expired(1001));
    }
}
