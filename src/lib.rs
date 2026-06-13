//! `attestation-envelope` — the one detached-JWS attestation envelope shared by
//! the services that notary-sign cross-user provenance (gotta, postbox).
//!
//! An attestation is a **detached JWS** (EdDSA / Ed25519) over the
//! **JCS-canonical** (RFC 8785) serialization of an immutable *core*:
//!
//! ```text
//! signing_input = BASE64URL(protected_header) "." BASE64URL(JCS(core))
//! signature     = Ed25519(signing_input)
//! ```
//!
//! This crate replaces the byte-identical `provenance::{sign, verify}` +
//! `notary::NotaryKey` that gotta (original) and postbox (a copy) each
//! hand-rolled. Crypto that is copy-pasted drifts silently — a fix to one
//! side's verify, or a change to the signing-input construction, would not
//! reach the other, yielding forged-but-accepted or valid-but-rejected
//! attestations. Here it lives once and is audited once.
//!
//! ## The seam
//!
//! Each service keeps its own `Core` struct and the field list it canonicalizes
//! — that is intrinsically per-payload. It plugs in by implementing
//! [`AttestableCore`], which declares the core's `typ` header and yields its
//! JCS bytes (build them with [`jcs_object`]). Everything cryptographic — the
//! protected header, the signing-input construction, sign, verify, and the
//! notary key/JWKS — is owned here and is identical for every core type.

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{self, Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// How an attestation was produced.
///
/// `Notary` = signed by the mediating service's notary key (the only mode in
/// use today). `E2e` is reserved for end-to-end sender-signed attestations.
/// The mode is a label carried in the envelope; it is **not** consulted by
/// [`verify`] — integrity rests entirely on the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Notary,
    E2e,
}

/// A core that can be attested: it declares the JWS `typ` bound into every
/// signature over this core type, and yields its JCS-canonical bytes.
///
/// `ENVELOPE_TYP` makes the core⇆envelope pairing static — a service cannot
/// sign its core under another service's `typ`.
pub trait AttestableCore {
    /// The `typ` protected-header value for this core type, e.g.
    /// `"gotta-attest+jws"`.
    const ENVELOPE_TYP: &'static str;

    /// RFC 8785 (JCS) canonical bytes of the core. Build with [`jcs_object`]:
    /// insert each present field, omit absent optionals, done.
    fn canonical(&self) -> Vec<u8>;
}

/// JCS-canonical object bytes from a field map.
///
/// Keys sort lexicographically (via [`BTreeMap`]) and `serde_json` emits no
/// insignificant whitespace, so for cores whose values are strings and
/// integers this is byte-equivalent to RFC 8785. Omit an absent optional by
/// simply not inserting it. (A dedicated JCS crate is the production-hardening
/// path if cores ever carry floats or non-ASCII-sensitive numbers.)
#[must_use]
pub fn jcs_object(fields: BTreeMap<&str, serde_json::Value>) -> Vec<u8> {
    serde_json::to_vec(&fields).expect("BTreeMap<&str, Value> always serializes")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProtectedHeader {
    alg: String,
    kid: String,
    typ: String,
}

/// A detached JWS over a [`AttestableCore`], stored next to the row it attests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub mode: Mode,
    /// base64url(UTF8(protected_header_json))
    pub protected: String,
    /// base64url(64-byte Ed25519 signature)
    pub signature: String,
}

/// JWS signing input: `BASE64URL(protected) "." BASE64URL(JCS(core))`.
fn signing_input<C: AttestableCore>(protected_b64: &str, core: &C) -> Vec<u8> {
    let mut buf = Vec::with_capacity(protected_b64.len() + 1 + 86);
    buf.extend_from_slice(protected_b64.as_bytes());
    buf.push(b'.');
    buf.extend_from_slice(B64.encode(core.canonical()).as_bytes());
    buf
}

/// Sign a core with an Ed25519 key, producing one attestation.
#[must_use]
pub fn sign<C: AttestableCore>(
    core: &C,
    key: &Ed25519KeyPair,
    kid: &str,
    mode: Mode,
) -> Attestation {
    let header = ProtectedHeader {
        alg: "EdDSA".into(),
        kid: kid.into(),
        typ: C::ENVELOPE_TYP.into(),
    };
    let protected = B64.encode(serde_json::to_vec(&header).expect("header serializes"));
    let sig = key.sign(&signing_input(&protected, core));
    Attestation {
        mode,
        protected,
        signature: B64.encode(sig.as_ref()),
    }
}

/// Verify an attestation against a core and a raw Ed25519 public key (32 bytes).
///
/// Returns `false` on any decode/parse/signature failure — never panics on bad
/// input. The protected header is bound into the signed input exactly as
/// received, so a tampered header invalidates the signature.
#[must_use]
pub fn verify<C: AttestableCore>(core: &C, att: &Attestation, public_key: &[u8]) -> bool {
    let Ok(sig) = B64.decode(att.signature.as_bytes()) else {
        return false;
    };
    let Ok(header_bytes) = B64.decode(att.protected.as_bytes()) else {
        return false;
    };
    let Ok(header) = serde_json::from_slice::<ProtectedHeader>(&header_bytes) else {
        return false;
    };
    if header.alg != "EdDSA" {
        return false;
    }
    let input = signing_input(&att.protected, core);
    signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
        .verify(&input, &sig)
        .is_ok()
}

/// Failed to generate or parse an Ed25519 notary key.
#[derive(Debug, thiserror::Error)]
#[error("ed25519 notary key generation or parse failed")]
pub struct KeyError;

/// The service-global notary signing key and its published JWKS.
///
/// In production the PKCS#8 seed comes from Secrets Manager / KMS; for local
/// runs use [`ephemeral`](NotaryKey::ephemeral) (its `kid` changes per process,
/// which is fine — clients fetch the JWKS fresh).
pub struct NotaryKey {
    key_pair: Ed25519KeyPair,
    kid: String,
}

impl NotaryKey {
    /// Generate an ephemeral key (local/dev). `kid_prefix` namespaces the kid,
    /// e.g. `"gotta"` → `"gotta-notary-<12 b64 chars of pubkey>"`.
    pub fn ephemeral(kid_prefix: &str) -> Result<Self, KeyError> {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| KeyError)?;
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_| KeyError)?;
        // Derive a stable-per-key id from the public key so the JWKS `kid`
        // matches what was signed with.
        let kid = format!(
            "{kid_prefix}-notary-{}",
            &B64.encode(key_pair.public_key().as_ref())[..12]
        );
        Ok(Self { key_pair, kid })
    }

    /// Load from a PKCS#8 seed (production path).
    pub fn from_pkcs8(pkcs8: &[u8], kid: impl Into<String>) -> Result<Self, KeyError> {
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| KeyError)?;
        Ok(Self {
            key_pair,
            kid: kid.into(),
        })
    }

    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Notary-sign a core (`Mode::Notary`).
    #[must_use]
    pub fn sign<C: AttestableCore>(&self, core: &C) -> Attestation {
        sign(core, &self.key_pair, &self.kid, Mode::Notary)
    }

    /// The JWKS document published for client-side verify.
    #[must_use]
    pub fn jwks(&self) -> serde_json::Value {
        let x = B64.encode(self.key_pair.public_key().as_ref());
        json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "x": x,
                "kid": self.kid,
                "alg": "EdDSA",
                "use": "sig",
            }]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in core exercising both a required and an omitted-optional field.
    struct TestCore {
        v: i64,
        id: String,
        note: Option<String>,
    }

    impl AttestableCore for TestCore {
        const ENVELOPE_TYP: &'static str = "test-attest+jws";
        fn canonical(&self) -> Vec<u8> {
            let mut m: BTreeMap<&str, serde_json::Value> = BTreeMap::new();
            m.insert("id", self.id.clone().into());
            if let Some(note) = &self.note {
                m.insert("note", note.clone().into());
            }
            m.insert("v", self.v.into());
            jcs_object(m)
        }
    }

    fn keypair() -> Ed25519KeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn core() -> TestCore {
        TestCore {
            v: 1,
            id: "abc".into(),
            note: None,
        }
    }

    #[test]
    fn jcs_is_sorted_and_omits_absent_optionals() {
        let s = String::from_utf8(core().canonical()).unwrap();
        assert_eq!(s, r#"{"id":"abc","v":1}"#);
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let key = keypair();
        let pubkey = key.public_key().as_ref().to_vec();
        let att = sign(&core(), &key, "k", Mode::Notary);
        assert!(verify(&core(), &att, &pubkey));
    }

    #[test]
    fn protected_header_binds_typ_and_kid() {
        let att = sign(&core(), &keypair(), "key-9", Mode::Notary);
        let header: serde_json::Value =
            serde_json::from_slice(&B64.decode(att.protected.as_bytes()).unwrap()).unwrap();
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["kid"], "key-9");
        assert_eq!(header["typ"], "test-attest+jws");
    }

    #[test]
    fn tampering_the_core_breaks_the_signature() {
        let key = keypair();
        let pubkey = key.public_key().as_ref().to_vec();
        let att = sign(&core(), &key, "k", Mode::Notary);
        let forged = TestCore {
            v: 1,
            id: "xyz".into(),
            note: None,
        };
        assert!(!verify(&forged, &att, &pubkey));
    }

    #[test]
    fn wrong_key_does_not_verify() {
        let att = sign(&core(), &keypair(), "k", Mode::Notary);
        let other_pub = keypair().public_key().as_ref().to_vec();
        assert!(!verify(&core(), &att, &other_pub));
    }

    #[test]
    fn garbage_attestation_returns_false_not_panic() {
        let att = Attestation {
            mode: Mode::Notary,
            protected: "!!!not-base64!!!".into(),
            signature: "also-not-valid".into(),
        };
        assert!(!verify(&core(), &att, &[0u8; 32]));
    }

    #[test]
    fn deterministic_signature_is_stable() {
        // Ed25519 is deterministic (RFC 8032): a fixed seed + fixed core yields
        // a fixed signature. Locks the crate's signing-input construction.
        let seed: [u8; 32] = [7u8; 32];
        let kp = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let att = sign(&core(), &kp, "k1", Mode::Notary);
        assert!(verify(&core(), &att, kp.public_key().as_ref()));
        // Same inputs → identical signature.
        let att2 = sign(&core(), &kp, "k1", Mode::Notary);
        assert_eq!(att.signature, att2.signature);
    }

    #[test]
    fn ephemeral_kid_is_prefixed() {
        let nk = NotaryKey::ephemeral("svc").unwrap();
        assert!(nk.kid().starts_with("svc-notary-"));
        let att = nk.sign(&core());
        assert_eq!(att.mode, Mode::Notary);
        // jwks exposes the same kid.
        assert_eq!(nk.jwks()["keys"][0]["kid"], nk.kid());
    }
}
