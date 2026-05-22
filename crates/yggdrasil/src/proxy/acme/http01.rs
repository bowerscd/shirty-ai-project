//! HTTP-01 challenge responder.
//!
//! The ACME spec's HTTP-01 challenge serves a key-authorization string
//! at `http://<host>/.well-known/acme-challenge/<token>`. yggdrasil's
//! `:80` redirect listener already owns the right path of every HTTPS
//! rule's IP, so the responder hooks in there: when a request hits
//! `.well-known/acme-challenge/<token>` and the token is registered,
//! the listener returns the key-auth as `text/plain`. Otherwise the
//! existing 301-to-HTTPS / 404 logic applies.
//!
//! Concurrency model: a single `Arc<RwLock<HashMap<String, String>>>`.
//! Registrations happen at issuance time (rare, one per host) and
//! lookups happen per HTTP request (cheap). The lock is taken read-only
//! on the hot path.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

/// Shared, clone-able HTTP-01 challenge responder.
///
/// The redirect listener pulls a clone of this and consults it on every
/// inbound HTTP request before falling through to the redirect logic.
#[derive(Debug, Clone, Default)]
pub struct AcmeResponder {
    inner: Arc<RwLock<HashMap<String, String>>>,
}

impl AcmeResponder {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a challenge token. The renewer calls this just before
    /// telling the ACME directory to validate; the matching
    /// [`AcmeResponder::deregister`] runs after the challenge is
    /// finalised (success or fail).
    pub fn register(&self, token: &str, key_auth: &str) {
        self.inner
            .write()
            .insert(token.to_string(), key_auth.to_string());
    }

    /// Remove a previously-registered token. Idempotent.
    pub fn deregister(&self, token: &str) {
        self.inner.write().remove(token);
    }

    /// Look up a token's key-authorization. Returns `None` for
    /// unregistered tokens. Called per HTTP request from the redirect
    /// listener — cheap (read lock + hash lookup).
    pub fn lookup(&self, token: &str) -> Option<String> {
        self.inner.read().get(token).cloned()
    }

    /// Number of pending challenges. Test/observability aid.
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}

/// The well-known prefix every HTTP-01 challenge URL begins with.
/// Exposed so the redirect listener can match on it cleanly.
pub const HTTP01_PATH_PREFIX: &str = "/.well-known/acme-challenge/";

/// Extract the bare challenge token from an inbound request path, or
/// `None` if the path doesn't match the HTTP-01 prefix. The token must
/// be base64url-style (alphanumeric, `_`, `-`); anything else is
/// rejected so we don't accidentally serve key-auth bytes for
/// `/.well-known/acme-challenge/../../etc/passwd`.
pub fn parse_challenge_path(path: &str) -> Option<&str> {
    let rest = path.strip_prefix(HTTP01_PATH_PREFIX)?;
    if rest.is_empty() {
        return None;
    }
    let valid = rest
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if !valid {
        return None;
    }
    Some(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_lookup_deregister_round_trip() {
        let r = AcmeResponder::new();
        assert!(r.is_empty());
        r.register("tok-1", "key-auth-1");
        assert_eq!(r.lookup("tok-1").as_deref(), Some("key-auth-1"));
        assert!(r.lookup("tok-2").is_none());
        r.deregister("tok-1");
        assert!(r.lookup("tok-1").is_none());
        // deregister of an unknown token is a no-op.
        r.deregister("never-existed");
    }

    #[test]
    fn parse_challenge_path_rejects_bad_inputs() {
        assert_eq!(
            parse_challenge_path("/.well-known/acme-challenge/abc123_-"),
            Some("abc123_-")
        );
        assert_eq!(parse_challenge_path("/.well-known/acme-challenge/"), None);
        assert_eq!(parse_challenge_path("/some/other/path"), None);
        // Path traversal attempts: `/` in the token portion is
        // disallowed by the alphabet check.
        assert_eq!(
            parse_challenge_path("/.well-known/acme-challenge/../etc/passwd"),
            None
        );
        assert_eq!(
            parse_challenge_path("/.well-known/acme-challenge/has space"),
            None
        );
    }
}
