---
title: "Encapsulated Evidence Transport with Detached Digest Binding"
abbrev: "Encapsulated Evidence Binding and Transport"
category: info

docname: draft-ritz-rats-encapsulated-evidence-transport-latest
submissiontype: IETF
v: 3
area: "Security"
workgroup: "Remote ATtestation ProcedureS"
keyword:
 - RATS
 - Remote Attestation
 - Background-Check Model
 - Detached Digest
 - ev_hash
 - ear_evidence_digest
 - Evidence Binding
venue:
  group: "Remote ATtestation ProcedureS"
  type: "Working Group"
  mail: "rats@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/rats/"
  github: "telephonicrobotics/securing-opaque-evidence"
  latest: "https://telephonicrobotics.github.io/securing-opaque-evidence/draft-ritz-rats-encapsulated-evidence-transport.html"

author:
 -
    fullname: Nathanael Ritz
    organization: Independent
    email: ietf@nritz.com

normative:
  RFC9052:
  RFC9334:
  RFC9449:
  RFC9530:
  RFC9711:
  RFC9901:
  RFC9999:

informative:
  I-D.ietf-rats-ear:
  I-D.ounsworth-rats-privacy-framework:
  I-D.ietf-seat-use-cases:
  I-D.ietf-lake-ra:
  RFC9528:
  OpenID.Core:
    title: "OpenID Connect Core 1.0 incorporating errata set 1"
    author:
      - ins: N. Sakimura
      - ins: J. Bradley
      - ins: M. Jones
      - ins: B. de Medeiros
      - ins: C. Mortimore
    date: 2014-11-08
    target: https://openid.net/specs/openid-connect-core-1_0.html

...

--- abstract

In the Background-Check Model of the Remote ATtestation procedureS (RATS) architecture ({{RFC9334}}), an Attester conveys Evidence to a Relying Party and forwards it to a Verifier. The Verifier appraises this Evidence and returns an Attestation Result to the Relying Party. When Evidence is encrypted or made opaque, certain cryptographic gaps may arise that cannot be solved by point-to-point security mechanisms alone. This draft aims to explore mitigation strategies when those gaps emerge.

--- middle

# Introduction {#intro}

## Applicability and Topological Scope {#scope}

The analysis and mechanisms in this document apply strictly to the decoupled RATS Background-Check Model where the Verifier is deployed as a remote network endpoint, topologically distinct from the Relying Party (RP), and where Evidence is confidentiality-protected (encrypted) for that Verifier.

When the RP and Verifier are co-located within the same trust boundary or host environment, the appraisal process acts on the Evidence locally. The local Verifier can directly evaluate inner claims and validate transport session binding values.

## The Limits of Point-to-Point Secure Transport Across Multi-Hop Chains {#transport-limits}

~~~
   +---------------------------------------+
   |                                       |
   |          +-----------------+          |
   |          | Remote Verifier |          |
   |          +-----------------+          |
   |              ^          |             |
   |    Forwarded |          | Attestation |
   |     Evidence |          | Result      |
   |    (enc_env) |          | (ev_hash)   |
   |              |          v             |
   |           +----------------+          |
   |           |  Relying Party |          |
   |           +----------------+          |
   |              ^                        |
   |     Evidence | (enc_env +             |
   |              |  session_binder)       |
   |              v                        |
   |           +----------------+          |
   |           |    Attester    |          |
   |           +----------------+          |
   |                                       |
   +---------------------------------------+
~~~
{: #fig-topology title="RATS Background-Check Model with Opaque Forwarding"}

Because the attestation workflow spans separate, decoupled connections—from the Attester to the Relying Party, and subsequently from the Relying Party to an external, transport-undefined Verifier endpoint—transport-layer security terminates at the Relying Party.

Normatively relying on a secure transport layer between the Relying Party and the Verifier, rather than establishing a self-contained cryptographic token at the object layer, introduces several architectural concerns:

1. **Middlebox Decoupling and Hop-by-Hop Breakdown:** In modern distributed deployments, the Relying Party and Verifier rarely maintain an unmediated, end-to-end transport pipe. Ingress controllers, API gateways, load balancers, and asynchronous event brokers (such as Kafka or pub/sub queues) frequently terminate TLS. Once transport terminates, channel security guarantees cease, exposing transit payloads to substitution, splicing, and misrouting by intermediary processes before reaching the appraisal engine.

2. **Loss of Self-Contained Object Security and Bearer Token Degeneration:** If an Attestation Result is only secure when ferried over a dedicated, private tunnel between the Relying Party and the Verifier, the token ceases to be a self-contained cryptographic object. Because the token commits only to temporal freshness (`session_binder_value`) and not to the wire payload (`ev_hash`), it degenerates into an ambient bearer token that can be detached from the original request context.

3. **Avoiding Layered Trust Recursion:** Remote attestation is explicitly designed to evaluate trust in an unverified endpoint from first principles. If the validity of an appraisal fundamentally depends on an assumed-secure, uncompromised transport channel to a Verifier, the protocol introduces circular trust recursion: the Relying Party must assume absolute network and host integrity across the verification path while in the process of scrutinizing trust in the primary connection.

As established in {{RFC9530}}, Section 1, transport-oriented integrity provides limited utility because it "is opaque to the application layer and only covers the extent of a single connection," failing across multi-hop topologies where messages travel over "a chain of separate connections" and risk data corruption, manipulation, or splicing between hops unless a transitive cryptographic link binds the disparate application-layer artifacts together.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

The following terms are used in this document:

* `enc_evidence`: An encrypted Evidence container (such as a Conceptual Messages Wrapper {{RFC9999}} encrypted via HPKE) addressed to the Verifier, which is treated as opaque ciphertext by the Relying Party.
* `ev_hash`: A detached cryptographic digest computed directly over the raw, serialized octets of the `enc_evidence` payload, conveyed in the `ear_evidence_digest` claim.
* `session_binder_value`: A connection-unique cryptographic value derived from the secure transport layer (e.g., a TLS exporter) that binds an Attester to the transport session.

# The Substitution Threat in Opaque Forwarding {#substitution-threat}

Per the proposed RATS Privacy Framework draft ({{I-D.ounsworth-rats-privacy-framework}}, Section 4.2), Evidence containing sensitive platform claims MUST be confidentiality-protected directly for the Verifier (e.g., via HPKE encapsulation) to prevent inspection and fingerprinting by intermediary nodes, including the Relying Party in the Background-Check model.

However, enforcing this confidentiality boundary forces the Relying Party to operate strictly as a blind forwarder unable to inspect inner claims or embedded session binders.

This topology creates an envelope substitution threat directly recognized in the SEAT threat model (Section 3.5.3 of {{I-D.ietf-seat-use-cases}} as proposed in active working drafts, "Encrypted Evidence and Blind Envelope Substitution"). In this scenario, an on-path attacker or untrusted proxy intercepts the in-flight encrypted Evidence envelope and substitutes an alternate valid envelope constructed against the same connection challenge.

In unencrypted attestation, the Relying Party appraises Evidence directly and detects measurement mismatches locally, while any on-wire modification alters the cumulative handshake transcript and causes the Attester's downstream signature (such as the peer's channel authentication proof-of-possession) to fail. When Evidence confidentiality is introduced to protect privacy, the Relying Party cannot inspect inner claims.

Because session binding values are frequently derivable from observable transport handshake parameters (such as key-share parameters, nonces, or cleartext handshake fields), an observer or co-tenant with access to an on-platform quoting engine can mint valid Evidence for an alternate workload bound to that same session challenge. If the Verifier's signed Attestation Result echoes only the temporal challenge (e.g., `session_binder_value`), it proves that the Verifier appraised *some* valid evidence containing that binder, but fails to establish payload correspondence to the specific ciphertext forwarded by the Relying Party. The Relying Party completes the connection, falsely attributing the substituted posture or workload identity to the active transport peer.

Normatively relying on secure transport between the Relying Party and the Verifier cannot bridge this gap, as channel security does not bind the Verifier's appraisal to the specific Evidence forwarded from the Attester's connection. Closing the substitution window requires a self-contained cryptographic token that explicitly locks the Verifier's appraisal statement to the raw wire bytes of the Evidence envelope (`ev_hash`).


# End-to-End Cryptographic Commitment via Detached Digests {#detached-digests}

To prevent intermediaries from adding, removing, or modifying forwarded data across decoupled boundaries, the authenticated statement must cryptographically commit to the exact bytes being transmitted.

This design mirrors established detached digest mechanisms across identity and transport specifications:

| Specification | Digest Claim | Bound Target Payload | Standard Reference |
| :--- | :--- | :--- | :--- |
| OpenID Connect Core 1.0 | `c_hash`, `at_hash` | Authorization Code, Access Token | {{OpenID.Core}}, Section 16.11 |
| OAuth 2.0 DPoP | `ath` | Access Token | {{RFC9449}}, Sections 4.2 & 11.8 |
| SD-JWT | `sd_hash` | Raw US-ASCII encoded Disclosures | {{RFC9901}}, Sections 4.3.1 & 9.10 |
| HTTP Digest Fields | `Digest` / `Repr-Digest` | Multi-hop message representation data | {{RFC9530}}, Sections 6.1–6.3 |
| EAT Attestation Results | `ear_evidence_digest` | Raw serialized `enc_evidence` ciphertext | Section 5 of [RFCthis] |
{: #digest-precedents title="Detached Digest Precedents in Object Security"}

As demonstrated in {{RFC9449}} and {{RFC9901}}, computing detached hashes over raw wire serializations without requiring intermediate parsing ensures that captured signatures cannot be spliced into alternate requests or envelopes.

Applying this principle to the opaque attestation wrapper requires the Verifier to compute a detached digest directly over the raw, serialized ciphertext bytes of the Evidence container (`ev_hash = Hash(enc_evidence)`) and embed this value within the signed Attestation Result.

Combining detached content digests with digital signatures fulfils the {{RFC9530}} model across multi-hop topologies. This allows the Relying Party to independently hash the received `enc_evidence` on the wire and assert equality against the Verifier's signed statement without requiring decryption keys or parsing capabilities, eliminating the substitution gap between the Attester-RP secure transport session and the verification channel.


# Claim Definition and Data Formats {#claim-definition}

This document proposes defining `ear_evidence_digest` as a top-level claim within the EAT Attestation Results (EAR) format ({{I-D.ietf-rats-ear}}):

~~~ cddl
; Extend the top-level EAR token socket
$$ear-extension //= (
  ? evidence-digest-label => evidence-digest-type
)

; Claim Key 1008
evidence-digest-label = eat.JC<"ear_evidence_digest", 1008>

; Representation supporting algorithm agility
evidence-digest-type = eat.JC<evidence-digest-json, evidence-digest-cbor>

evidence-digest-json = {
  digest-alg-label => text,                  ; Hash algorithm name (e.g., "sha-256", "sha-384")
  digest-val-label => cmw.base64url-string   ; Base64URL-encoded detached digest
}

evidence-digest-cbor = {
  digest-alg-label => int / text,            ; COSE Algorithm ID (e.g., -16 for SHA-256) or text
  digest-val-label => bytes                  ; Raw binary digest octets
}

digest-alg-label = eat.JC<"alg", 1>
digest-val-label = eat.JC<"val", 2>
~~~

This compact structure conveys the digest value alongside an explicit algorithm identifier, ensuring algorithm agility while committing directly to the raw wire bytes of the opaque evidence envelope.

## Illustrative Workflow {#workflow}

~~~
   Attester                  Relying Party                   Verifier
      |                            |                             |
      | 1. enc_evidence            |                             |
      |    (channel-bound)         |                             |
      |--------------------------->|                             |
      |                            | 2. enc_evidence,            |
      |                            |    freshness challenge      |
      |                            |---------------------------->|
      |                            |                             | 3. Appraise &
      |                            |                             |    compute H_v
      |                            | 4. Attestation Result       |
      |                            |    (ear_evidence_digest)    |
      |                            |<----------------------------|
      |                            |                             |
      |                            | 5. Assert:                  |
      |                            |    H_wire == H_v            |
~~~
{: #fig-workflow title="Encapsulated Evidence Workflow"}

Across this topology, the workflow operates as follows:

1. **Handshake and Evidence Presentation:** The Attester encapsulates its Evidence into an opaque ciphertext container (`enc_evidence`) targeted to the Verifier's public key. It transmits `enc_evidence` to the Relying Party within the secure transport session and commits to the wire octets within the channel transcript (e.g., via an Attested TLS handshake transcript signature {{I-D.ietf-seat-use-cases}} or the Attester's channel authentication signature covering external authorization data carrying the envelope {{I-D.ietf-lake-ra}}).
2. **Blind Forwarding:** Upon receiving `enc_evidence`, the Relying Party buffers the raw, unaltered wire octets and computes a local digest: `H_wire = Hash(enc_evidence)`. It forwards `enc_evidence` to the Verifier alongside a session freshness challenge (e.g., `eat_nonce`).
3. **Appraisal and Digest Binding:** The Verifier decrypts and appraises the enclosed Evidence according to local appraisal policies, computes the detached digest `H_v = Hash(enc_evidence)` over the raw received octets using the negotiated hash algorithm, and returns a signed Attestation Result (recommended as an EAR token per {{I-D.ietf-rats-ear}}) embedding `H_v` in the `ear_evidence_digest` claim and echoing the freshness challenge.
4. **Appraisal Verification:** The Relying Party receives the signed Attestation Result, verifies the Verifier's digital signature, validates freshness, and asserts strict equality: `H_wire == ear_evidence_digest.val`. If the digests match, the Relying Party accepts that the Verifier appraised the exact payload forwarded from the transport channel. If a mismatch occurs, the Relying Party aborts the session.

# Cryptographic and Agility Considerations {#crypto-considerations}

* **Collision Resistance:** The hash algorithm used to generate `ev_hash` MUST be cryptographically collision-resistant. Implementations MUST support SHA-256 and SHOULD support SHA-384 and SHA-512. Algorithms known to be broken or weakened against collisions (e.g., MD5, SHA-1) MUST NOT be used.
* **Algorithm Agility:** The `ear_evidence_digest` structure pairs the digest value with an explicit algorithm identifier (such as COSE algorithm identifiers in CBOR or IANA hash names in JSON), enabling independent cryptographic evolution.
* **Wire Serialization Invariance:** The digest MUST be computed over the raw wire octets of the serialized `enc_evidence` ciphertext. Intermediaries MUST NOT re-encode, normalize, or canonicalize the envelope between transport and verification.

# IANA Considerations {#iana}

This document does not request independent IANA registry actions. Instead, it recommends that the RATS Working Group register the `ear_evidence_digest` claim in the "JSON Web Token Claims" and "CBOR Web Token Claims" registries as part of progressing the EAT Attestation Results (EAR) specification ({{I-D.ietf-rats-ear}}), populated as follows:

* Claim Name: `ear_evidence_digest`
* Claim Description: Detached Digest of Forwarded Evidence Envelope
* JWT Claim Name: `ear_evidence_digest`
* Claim Key: 1008 (suggested)
* Claim Value Type(s): map
* Change Controller: IESG
* Specification Document(s): Section 4 of [RFCthis]

# Security Considerations {#security}

## The Dual-Boundary Defense {#dual-boundary}

The security architecture of encapsulated Evidence transport in the RATS Background-Check model depends upon two orthogonal cryptographic boundaries operating in tandem:

1. **The Confidentiality Boundary:** Established via asymmetric payload encapsulation (such as HPKE targeting the Verifier). This boundary prevents on-path intermediaries and transport proxies from inspecting inner Evidence claims or extracting ephemeral identity and signing keys (e.g., ephemeral Target Signing Keys bound to transport sessions). Under nominal operating conditions where encapsulation keys remain strictly confidential, an attacker cannot inspect the inner payload to bind extracted ephemeral material into an alternate envelope.
2. **The Integrity Boundary:** Established via detached digest verification (`ev_hash` via `ear_evidence_digest`). This boundary cryptographically binds the raw, wire-format ciphertext delivered to the Relying Party directly to the Verifier's signed appraisal statement.

Rather than treating detached digest binding as a redundant mechanism, the protocol treats `ev_hash` as an indispensable defense-in-depth fail-safe against breakdown of the confidentiality boundary. In practical deployments, confidentiality boundaries may fail due to Verifier decryption key exposure, key confusion across multi-tenant appraisal endpoints, or protocol architectures employing offloaded transport termination proxies.

In a secure transport channel—such as Attested TLS {{I-D.ietf-seat-use-cases}} or LAKE RA over EDHOC ({{I-D.ietf-lake-ra}})—the Attester proves possession of its transport identity key by generating a signed proof of possession. Because an on-path attacker lacks the Attester's private signing key, the attacker cannot alter the ciphertext sitting on the Relying Party's wire without causing the transport channel authentication to fail immediately.

Even if the confidentiality layer is compromised, exposing inner Evidence claims to an eavesdropper, an on-path attacker cannot successfully substitute a forged or alternate Evidence envelope for an active transport session when the Relying Party strictly enforces `ev_hash` verification. Appraising an altered or substituted Evidence wrapper forces the Verifier to compute a digest over the substituted wire octets. Because the attacker cannot alter the original wire ciphertext committed to the Attester's transport channel signature, and cannot forge the Verifier's digital signature over the original ciphertext's hash, the Relying Party will detect the digest mismatch between the received wire payload and the Attestation Result and abort the session.

Conversely, relying solely on Evidence confidentiality without detached digest verification leaves the system vulnerable to envelope substitution and splicing attacks, as described in {{mitm-relay}}.

{{dual-boundary-matrix}} summarizes the resulting security posture across both operational boundaries.

| Confidentiality Boundary | ev_hash Verification Enforced | ev_hash Verification Omitted |
| :--- | :--- | :--- |
| **Intact** (Encapsulation Secret) | **Secure (Full Defense)**: Payload privacy preserved; wire envelope transitively bound to appraisal. | **Vulnerable (Splicing Hazard)**: Blind forwarder cannot detect out-of-band envelope substitution ({{mitm-relay}}). |
| **Broken** (Key Exposure) | **Secure (Fail-Safe Active)**: Channel transcript pinning and signed digest mismatch reject forged envelope. | **Insecure (Session Subversion)**: Attacker extracts session keys and splices arbitrary forged envelopes. |
{: #dual-boundary-matrix title="Dual-Boundary Defense Matrix"}

## Envelope Splicing and Blind Forwarding Hazards {#mitm-relay}

When a Relying Party acts as a blind forwarder and skips detached digest verification—relying exclusively on temporal freshness identifiers (such as session nonces or transport-derived binders) and key-binding claims—the protocol becomes vulnerable to asynchronous envelope splicing and cross-session substitution attacks ({{I-D.ietf-seat-use-cases}}, Section 3.5.3).

If the Relying Party does not verify that the digest embedded in the Verifier's signed Attestation Result matches the exact bytes received on its transport wire, an on-path attacker or compromised proxy can decouple the transport session from the verification exchange. Submitting an alternate valid envelope to the Verifier out-of-band yields an authentic Attestation Result that satisfies binder freshness and signature verification, while appraising a completely different workload or configuration.

This vulnerability does not stem from a deficiency in the Attester-to-RP connection: that hop is already bound by the transport signature, which prevents wire tampering on that link. Instead, the cryptographic gap lies strictly between the received wire octets and the Verifier's appraisal. Detached digest binding (`ev_hash`) eliminates this gap by making the Attestation Result a self-contained cryptographic object. By asserting strict equality between the wire digest and the signed `ear_evidence_digest`, the Relying Party ensures that if it is negotiating with workload instance B, its appraisal policy evaluates the Verifier's appraisal of that exact instance B, independent of whether the Relying Party and Verifier communicate over a direct tunnel, a multi-hop intermediary, or an untrusted broker.

## Scope and Upstream Authority Bounds {#authority-bounds}

Detached envelope binding guarantees transport custody and wire-format payload correspondence across a decoupled three-party topology (Attester, Relying Party, and Verifier). It explicitly does not protect against vulnerabilities arising from corrupted, compromised, or misconfigured appraisal authorities external to the transport path.

Specifically, the use of a binding digest value does not defend against:

* **Compromised Reference Value Authorities:** If the private key of a Reference Value Provider (RVP) is compromised, an adversary can sign forged reference manifests that assert trust in attacker-selected measurements or malicious configurations. When the Verifier appraises Evidence containing those measurements, it evaluates them against the validly signed (but malicious) manifest, concluding that the workload conforms to policy. The Verifier will subsequently issue a valid Attestation Result with an accurate `ev_hash` binding.
* **Compromised Endorsement Signers:** If an authority issuing Key Endorsements or Attestation Key certificates is compromised, invalid provenance statements will be accepted by the Verifier as authentic.

The detached digest mechanism ensures that the Evidence evaluated by the Verifier is byte-for-byte identical to the Evidence forwarded by the Relying Party. It provides transit integrity and non-substitution, not upstream appraisal truth. Relying Parties must ensure that appraisal policy validation and trust anchors for Reference Value Providers and Endorsement Signers are maintained independently of the transport encapsulation layer.


--- back

# Acknowledgments
{:numbered="false"}

TODO
