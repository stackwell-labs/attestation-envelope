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
///
/// Every field here is covered by the signature: `protected` is bound into the
/// signing input verbatim, and `signature` is the signature itself. Do not add
/// a field to this struct that [`signing_input`] does not cover — an
/// unauthenticated field inside a security envelope is a field a reader may
/// trust and an attacker with at-rest write access may edit. (A `mode`
/// discriminant lived here until v0.3.0 and was exactly that: uncovered,
/// unread, and freely mutable.) Anything that must be authenticated belongs in
/// [`ProtectedHeader`] or in the core.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// base64url(UTF8(protected_header_json))
    pub protected: String,
    /// base64url of the 64-byte signature — Ed25519, or JOSE fixed `r||s` for ES256.
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
pub fn sign<C: AttestableCore>(core: &C, key: &Ed25519KeyPair, kid: &str) -> Attestation {
    let header = ProtectedHeader {
        alg: "EdDSA".into(),
        kid: kid.into(),
        typ: C::ENVELOPE_TYP.into(),
    };
    let protected = B64.encode(serde_json::to_vec(&header).expect("header serializes"));
    let sig = key.sign(&signing_input(&protected, core));
    Attestation {
        protected,
        signature: B64.encode(sig.as_ref()),
    }
}

/// Verify an attestation against a core and the signer's public key.
///
/// Dispatches on the protected `alg`:
/// - `EdDSA` — `public_key` is the 32-byte raw Ed25519 key.
/// - `ES256` — `public_key` is the 65-byte uncompressed P-256 point
///   (`0x04 || x || y`); the signature is JOSE fixed-form `r||s` (64 bytes).
///
/// Any other `alg` is rejected. Returns `false` on any decode/parse/signature
/// failure — never panics on bad input. The protected header is bound into the
/// signed input exactly as received, so a tampered header (including a swapped
/// `alg`) invalidates the signature; a key whose type doesn't match `alg` simply
/// fails to verify, so the two algorithms cannot be confused.
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
    let alg: &'static dyn signature::VerificationAlgorithm = match header.alg.as_str() {
        "EdDSA" => &signature::ED25519,
        "ES256" => &signature::ECDSA_P256_SHA256_FIXED,
        _ => return false,
    };
    let input = signing_input(&att.protected, core);
    signature::UnparsedPublicKey::new(alg, public_key)
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

    /// Notary-sign a core with this service's notary key.
    #[must_use]
    pub fn sign<C: AttestableCore>(&self, core: &C) -> Attestation {
        sign(core, &self.key_pair, &self.kid)
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

/// ES256 / P-256 notary signing custodied in AWS KMS — the private key never
/// leaves KMS; each signature is one KMS `Sign` call over the signing input.
/// Behind the `kms` feature so EdDSA-only consumers don't pull the AWS SDK.
///
/// Produces `alg: "ES256"` attestations that [`verify`] checks against the
/// 65-byte uncompressed P-256 point ([`KmsNotary::public_point`] / the JWKS).
#[cfg(feature = "kms")]
pub mod kms {
    use super::{signing_input, AttestableCore, Attestation, ProtectedHeader, B64};
    use base64::Engine;
    use serde_json::json;

    use aws_sdk_kms::primitives::Blob;
    use aws_sdk_kms::types::{MessageType, SigningAlgorithmSpec};
    use aws_sdk_kms::Client as KmsClient;

    /// A KMS-backed ES256 signing failure (key fetch, sign call, or malformed
    /// KMS output).
    #[derive(Debug, thiserror::Error)]
    pub enum KmsError {
        #[error("KMS GetPublicKey failed: {0}")]
        GetPublicKey(String),
        #[error("KMS Sign failed: {0}")]
        Sign(String),
        #[error("KMS returned a malformed {0}")]
        Malformed(&'static str),
    }

    /// The service-global ES256 notary, custodied in AWS KMS.
    ///
    /// [`new`](KmsNotary::new) fetches the public key once (for a stable `kid` +
    /// the JWKS); each [`sign`](KmsNotary::sign) is one KMS `Sign` call whose DER
    /// ECDSA output is converted to the 64-byte JOSE form.
    pub struct KmsNotary {
        client: KmsClient,
        key_id: String,
        kid: String,
        /// Uncompressed SEC1 point: `0x04 || x(32) || y(32)`.
        point: [u8; 65],
    }

    impl KmsNotary {
        /// Build from a KMS key id/ARN (an asymmetric `ECC_NIST_P256`,
        /// `SIGN_VERIFY` key). `kid_prefix` namespaces the JWKS `kid`, e.g.
        /// `"gotta"` → `"gotta-notary-<12 b64 chars of the point>"`. The kid is
        /// stable across cold starts because the KMS key is stable.
        pub async fn new(
            client: KmsClient,
            key_id: impl Into<String>,
            kid_prefix: &str,
        ) -> Result<Self, KmsError> {
            let key_id = key_id.into();
            let resp = client
                .get_public_key()
                .key_id(&key_id)
                .send()
                .await
                .map_err(|e| KmsError::GetPublicKey(e.to_string()))?;
            let spki = resp
                .public_key()
                .ok_or(KmsError::Malformed("GetPublicKey response (no key)"))?
                .as_ref();
            let point = ec_point_from_spki(spki)?;
            let kid = format!("{kid_prefix}-notary-{}", &B64.encode(point)[..12]);
            Ok(Self {
                client,
                key_id,
                kid,
                point,
            })
        }

        #[must_use]
        pub fn kid(&self) -> &str {
            &self.kid
        }

        /// The uncompressed P-256 point (`0x04 || x || y`) — the public-key bytes
        /// [`super::verify`] expects for an `ES256` attestation.
        #[must_use]
        pub fn public_point(&self) -> &[u8; 65] {
            &self.point
        }

        /// Notary-sign a core via KMS → an ES256 attestation.
        pub async fn sign<C: AttestableCore>(&self, core: &C) -> Result<Attestation, KmsError> {
            let header = ProtectedHeader {
                alg: "ES256".into(),
                kid: self.kid.clone(),
                typ: C::ENVELOPE_TYP.into(),
            };
            let protected = B64.encode(serde_json::to_vec(&header).expect("header serializes"));
            let input = signing_input(&protected, core);
            let resp = self
                .client
                .sign()
                .key_id(&self.key_id)
                .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
                .message_type(MessageType::Raw)
                .message(Blob::new(input))
                .send()
                .await
                .map_err(|e| KmsError::Sign(e.to_string()))?;
            let der = resp
                .signature()
                .ok_or(KmsError::Malformed("Sign response (no signature)"))?
                .as_ref();
            let raw = der_ecdsa_to_p256_fixed(der)?;
            Ok(Attestation {
                protected,
                signature: B64.encode(raw),
            })
        }

        /// The JWKS document (one EC P-256 key) for client-side verify.
        #[must_use]
        pub fn jwks(&self) -> serde_json::Value {
            let x = B64.encode(&self.point[1..33]);
            let y = B64.encode(&self.point[33..65]);
            json!({
                "keys": [{
                    "kty": "EC",
                    "crv": "P-256",
                    "x": x,
                    "y": y,
                    "kid": self.kid,
                    "alg": "ES256",
                    "use": "sig",
                }]
            })
        }
    }

    /// Extract the 65-byte uncompressed EC point from a DER SubjectPublicKeyInfo.
    /// For P-256 the SPKI's trailing 65 bytes are the BIT STRING content
    /// (`0x04 || x(32) || y(32)`); validate the length + the `0x04` prefix.
    fn ec_point_from_spki(spki: &[u8]) -> Result<[u8; 65], KmsError> {
        if spki.len() < 65 {
            return Err(KmsError::Malformed("SPKI (too short)"));
        }
        let tail = &spki[spki.len() - 65..];
        if tail[0] != 0x04 {
            return Err(KmsError::Malformed("SPKI (not an uncompressed point)"));
        }
        let mut point = [0u8; 65];
        point.copy_from_slice(tail);
        Ok(point)
    }

    /// Convert a DER ECDSA-P256 signature (`SEQUENCE { INTEGER r, INTEGER s }`)
    /// to the 64-byte JOSE fixed form (`r||s`, each left-padded to 32 bytes).
    fn der_ecdsa_to_p256_fixed(der: &[u8]) -> Result<[u8; 64], KmsError> {
        let bad = || KmsError::Malformed("ECDSA DER signature");
        if der.len() < 8 || der[0] != 0x30 {
            return Err(bad());
        }
        // SEQUENCE length is short-form (< 128) for a P-256 signature.
        let mut i = 2usize;
        let mut read_int = |buf: &[u8]| -> Result<Vec<u8>, KmsError> {
            if i + 2 > buf.len() || buf[i] != 0x02 {
                return Err(bad());
            }
            let len = buf[i + 1] as usize;
            let start = i + 2;
            let end = start.checked_add(len).ok_or_else(bad)?;
            if end > buf.len() {
                return Err(bad());
            }
            i = end;
            Ok(buf[start..end].to_vec())
        };
        let r = read_int(der)?;
        let s = read_int(der)?;
        let mut out = [0u8; 64];
        place_be(&r, &mut out[0..32])?;
        place_be(&s, &mut out[32..64])?;
        Ok(out)
    }

    /// Right-align a big-endian integer into a fixed slot, stripping DER
    /// sign-padding leading zeros and rejecting an overlong value.
    fn place_be(int: &[u8], slot: &mut [u8]) -> Result<(), KmsError> {
        let mut v = int;
        while v.len() > 1 && v[0] == 0x00 {
            v = &v[1..];
        }
        if v.len() > slot.len() {
            return Err(KmsError::Malformed("ECDSA integer (overlong)"));
        }
        let off = slot.len() - v.len();
        slot[off..].copy_from_slice(v);
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ring::rand::SystemRandom;
        use ring::signature::{
            self, EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED,
        };

        #[test]
        fn der_to_fixed_then_verifies_against_ring() {
            let rng = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
            let kp =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                    .unwrap();
            let msg = b"attestation signing input";
            let der = kp.sign(&rng, msg).unwrap(); // DER, exactly like KMS returns
            let fixed = der_ecdsa_to_p256_fixed(der.as_ref()).unwrap();
            signature::UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, kp.public_key().as_ref())
                .verify(msg, &fixed)
                .expect("the converted JOSE-fixed signature verifies");
        }

        #[test]
        fn ec_point_extracted_from_spki_tail() {
            // <prefix> || 0x04 || x(32) || y(32) — assert the trailing-65 extractor.
            let mut spki = vec![0u8; 26];
            spki.push(0x04);
            spki.extend_from_slice(&[7u8; 64]);
            let pt = ec_point_from_spki(&spki).unwrap();
            assert_eq!(pt[0], 0x04);
            assert_eq!(&pt[1..], &[7u8; 64][..]);
        }

        #[test]
        fn malformed_der_is_rejected_not_panic() {
            assert!(der_ecdsa_to_p256_fixed(&[0x30, 0x00]).is_err());
            assert!(der_ecdsa_to_p256_fixed(b"not-der").is_err());
        }
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
        let att = sign(&core(), &key, "k");
        assert!(verify(&core(), &att, &pubkey));
    }

    #[test]
    fn protected_header_binds_typ_and_kid() {
        let att = sign(&core(), &keypair(), "key-9");
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
        let att = sign(&core(), &key, "k");
        let forged = TestCore {
            v: 1,
            id: "xyz".into(),
            note: None,
        };
        assert!(!verify(&forged, &att, &pubkey));
    }

    #[test]
    fn wrong_key_does_not_verify() {
        let att = sign(&core(), &keypair(), "k");
        let other_pub = keypair().public_key().as_ref().to_vec();
        assert!(!verify(&core(), &att, &other_pub));
    }

    #[test]
    fn es256_attestation_verifies_via_alg_dispatch() {
        // Build an ES256 attestation the way the KMS notary would (alg "ES256",
        // JOSE fixed r||s) using a local P-256 key, and confirm verify() routes
        // it to the P-256 path against the 65-byte uncompressed point.
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        let point = kp.public_key().as_ref().to_vec(); // 65-byte uncompressed
        let header = ProtectedHeader {
            alg: "ES256".into(),
            kid: "es-1".into(),
            typ: TestCore::ENVELOPE_TYP.into(),
        };
        let protected = B64.encode(serde_json::to_vec(&header).unwrap());
        let input = signing_input(&protected, &core());
        let sig = kp.sign(&rng, &input).unwrap(); // FIXED → 64-byte r||s
        let att = Attestation {
            protected,
            signature: B64.encode(sig.as_ref()),
        };
        assert!(verify(&core(), &att, &point));
        // An Ed25519 key (wrong type for ES256) must not verify — no alg confusion.
        assert!(!verify(&core(), &att, keypair().public_key().as_ref()));
        // Tampering the core still breaks it under ES256.
        let forged = TestCore {
            v: 2,
            id: "abc".into(),
            note: None,
        };
        assert!(!verify(&forged, &att, &point));
    }

    #[test]
    fn garbage_attestation_returns_false_not_panic() {
        let att = Attestation {
            protected: "!!!not-base64!!!".into(),
            signature: "also-not-valid".into(),
        };
        assert!(!verify(&core(), &att, &[0u8; 32]));
    }

    /// Attestations written before v0.3.0 carry a `"mode"` key. The field was
    /// never covered by the signature, so dropping it is not a wire break:
    /// stored envelopes must still parse (unknown key ignored) and still
    /// verify. Granite has such rows in its decision table.
    #[test]
    fn pre_v0_3_attestation_with_mode_still_parses_and_verifies() {
        let kp = keypair();
        let att = sign(&core(), &kp, "k");
        let legacy = serde_json::json!({
            "mode": "notary",
            "protected": att.protected,
            "signature": att.signature,
        });
        let parsed: Attestation = serde_json::from_value(legacy).unwrap();
        assert!(verify(&core(), &parsed, kp.public_key().as_ref()));
    }

    #[test]
    fn deterministic_signature_is_stable() {
        // Ed25519 is deterministic (RFC 8032): a fixed seed + fixed core yields
        // a fixed signature. Locks the crate's signing-input construction.
        let seed: [u8; 32] = [7u8; 32];
        let kp = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let att = sign(&core(), &kp, "k1");
        assert!(verify(&core(), &att, kp.public_key().as_ref()));
        // Same inputs → identical signature.
        let att2 = sign(&core(), &kp, "k1");
        assert_eq!(att.signature, att2.signature);
    }

    #[test]
    fn ephemeral_kid_is_prefixed() {
        let nk = NotaryKey::ephemeral("svc").unwrap();
        assert!(nk.kid().starts_with("svc-notary-"));
        let att = nk.sign(&core());
        assert!(verify(
            &core(),
            &att,
            nk.key_pair.public_key().as_ref()
        ));
        // jwks exposes the same kid.
        assert_eq!(nk.jwks()["keys"][0]["kid"], nk.kid());
    }
}
