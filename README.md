# attestation-envelope

One audited detached-JWS attestation envelope — the single source of truth for
how the platform's mediating services notary-sign cross-user provenance. It
replaces the byte-identical `provenance::{sign, verify}` + `notary::NotaryKey`
that **gotta** (original) and **postbox** (a copy) each hand-rolled.

Copy-pasted crypto drifts silently: a fix to one side's `verify`, or a change
to how the signing input is built, would never reach the other — yielding
forged-but-accepted or valid-but-rejected attestations. This crate makes that
impossible by owning the cryptographic envelope once.

## The contract

An attestation is a **detached JWS** (EdDSA / Ed25519) over the **JCS-canonical**
(RFC 8785) bytes of an immutable *core*:

```text
signing_input = BASE64URL(protected_header) "." BASE64URL(JCS(core))
signature     = Ed25519(signing_input)
```

The protected header is `{"alg":"EdDSA","kid":…,"typ":…}` (field order is
normative — it is part of the signed bytes).

## What it owns vs. what stays per-service

- **Owned here:** `sign`, `verify`, the protected-header shape, the
  signing-input construction, `Mode`, `Attestation`, and `NotaryKey` (Ed25519
  key gen / PKCS#8 load / JWKS). Identical for every core.
- **Per-service:** the `Core` struct and the field list it canonicalizes — that
  is intrinsically per-payload. A service plugs in by implementing
  `AttestableCore` (declare `ENVELOPE_TYP`, return JCS bytes via `jcs_object`).

```rust
use std::collections::BTreeMap;
use attestation_envelope::{AttestableCore, jcs_object};

struct MyCore { v: i64, id: String, note: Option<String> }

impl AttestableCore for MyCore {
    const ENVELOPE_TYP: &'static str = "myservice-attest+jws";
    fn canonical(&self) -> Vec<u8> {
        let mut m: BTreeMap<&str, serde_json::Value> = BTreeMap::new();
        m.insert("id", self.id.clone().into());
        if let Some(n) = &self.note { m.insert("note", n.clone().into()); }
        m.insert("v", self.v.into());
        jcs_object(m)
    }
}

let notary = attestation_envelope::NotaryKey::ephemeral("myservice")?;
let att = notary.sign(&core);
assert!(attestation_envelope::verify(&core, &att, pubkey));
```

## Wire stability

`ENVELOPE_TYP` and the field order of the protected header are part of the
signed bytes. gotta's cross-language interop vector (its Rust suite vs. an
independent JS WebCrypto implementation) pins the exact `gotta-attest+jws`
output; that test stays in gotta and fails loudly if this crate ever changes
the envelope construction.

## License

MIT OR Apache-2.0.
