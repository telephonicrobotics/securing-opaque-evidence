---
title: "Encapsulated Evidence Transport with Detached Digest Binding"
abbrev: "Encapsulated Evidence Binding and Transport"
category: std

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
  RFC2119:
  RFC8174:
  RFC9052:
  RFC9334:
  RFC9449:
  RFC9530:
  RFC9711:
  RFC9901:

informative:
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

In the Background-Check Model of the Remote ATtestation procedureS (RATS) architecture (RFC 9334), an Attester conveys Evidence to a Relying Party, which treats it as opaque ciphertext and forwards it to a Verifier. Operating across this three-party topological triangle introduces an envelope substitution gap when transport-layer security terminates at the Relying Party. This document specifies a detached digest claim, `ev_hash`, embedded within the Verifier's signed Attestation Result. By cryptographically binding the raw ciphertext of the forwarded Evidence container to the appraisal statement, this mechanism establishes end-to-end integrity and payload correspondence across decoupled transport boundaries.

--- middle

# Introduction {#intro}

In the Background-Check Model of the Remote ATtestation procedureS (RATS) architecture ({{RFC9334}}), an Attester conveys Evidence to a Relying Party, which treats it as opaque and forwards it to a Verifier. The Verifier appraises this Evidence and returns an Attestation Result to the Relying Party, forming a distinct three-party topological triangle.

~~~ ascii-art
                +---------------------------------------+
                |                                       |
                |           +----------------+          |
                |           |    Verifier    |          |
                |           +----------------+          |
                |              ^          |             |
                |    Forwarded |          | Attestation |
                |     Evidence |          | Result      |
                |    (enc_cmw) |          | (ev_hash)   |
                |              |          v             |
                |           +----------------+          |
                |           |  Relying Party |          |
                |           +----------------+          |
                |              ^                        |
                |     Evidence | (enc_cmw +             |
                |              |  session_binder)       |
                |              v                        |
                |           +----------------+          |
                |           |    Attester    |          |
                |           +----------------+          |
                |                                       |
                +---------------------------------------+
~~~
{: #fig-topology title="RATS Background-Check Model with Opaque Forwarding"}

Operating within this triangle introduces fundamental security gaps that cannot be solved by point-to-point security mechanisms alone, requiring cryptographic payload binding derived from three core principles:

1. Recognizing the boundaries of transport-level security across multi-hop topologies.
2. Mitigating opaque envelope substitution when intermediaries forward encrypted artifacts.
3. Establishing end-to-end cryptographic commitment via detached digests over wire-format representations.

This document defines the `ev_hash` claim for inclusion in Attestation Results (such as those based on the Entity Attestation Token {{RFC9711}}), defining normative rules for generation, encapsulation, and Relying Party verification.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses terms defined in {{RFC9334}}, specifically "Attester", "Relying Party", "Verifier", "Evidence", and "Attestation Result". The label `enc_cmw` refers to an encapsulated, encrypted Evidence envelope (such as a Concise Message Wrapper encrypted via HPKE).


# Problem Statement and Threat Model {#problem-statement}

## The Limits of Point-to-Point Secure Transport Across Multi-Hop Chains {#transport-limits}

While a secure transport protocol establishes session-level authenticity and derives a connection-unique `session_binder_value` between the Attester and the Relying Party, this protection is opaque to the application layer and covers only the extent of a single transport connection.

Because the attestation workflow spans separate, decoupled connections—from the Attester to the Relying Party, and subsequently from the Relying Party to an external, transport-undefined Verifier endpoint—transport-layer security terminates at the Relying Party.

As established in {{RFC9530}}, Section 1, transport-oriented integrity provides limited utility because it "is opaque to the application layer and only covers the extent of a single connection," failing across multi-hop topologies where messages travel over "a chain of separate connections" and risk data corruption, manipulation, or splicing between hops unless a transitive cryptographic link binds the disparate application-layer artifacts together.

## The Substitution Threat in Opaque Forwarding {#substitution-threat}

When Evidence is confidentiality-protected for the Verifier (e.g., using HPKE-encapsulated CMWs, or `enc_cmw`) to satisfy data minimization mandates, the Relying Party operates strictly as a blind forwarder unable to inspect inner claims or embedded session binders.

This topology creates an envelope substitution threat directly analogous to the Token Substitution attack identified in OpenID Connect Core 1.0 (Section 16.11) [{{OpenID.Core}}], where detached hashes (`c_hash` and `at_hash`) are required to "prevent Authorization Code substitution" and "Access Token substitution."

{{RFC9449}} (OAuth 2.0 DPoP), Section 7, defines this exact failure mode: without binding the payload to the proof, "a captured signature applied to AT1 could be replayed with AT2 instead, changing the rights and access of the intended request." The binding ensures that a proof cannot "be used with multiple different access token values across different requests."

If the Verifier's signed Attestation Result echoes only the temporal challenge (`session_binder_value`), it proves that the Verifier appraised some valid evidence containing that binder, but fails to prove payload correspondence to the specific ciphertext forwarded by the Relying Party.

Without cryptographic commitment over the opaque envelope, an attacker or compromised channel can substitute the in-flight `enc_cmw` with a different valid envelope evaluated against the same binder, altering the security posture of the intended session without detection.


# Detached Digest Architecture (ev_hash) {#architecture}

## End-to-End Cryptographic Commitment Principles {#commitment-principles}

To prevent intermediaries from adding, removing, or modifying forwarded data across decoupled boundaries, the authenticated statement must cryptographically commit to the exact bytes being transmitted.

{{RFC9901}} (SD-JWT), Section 9.10, establishes that while individual claims may be protected in isolation, "the specific set of Disclosures, however, is not integrity protected; the SD-JWT can be modified by adding or removing Disclosures and still be valid." Only an end-to-end detached signature over the envelope ensures that "no intermediate party has added, removed, or modified the list of Disclosures."

Per {{RFC9901}} (Section 4.3.1), this binding is achieved via the `sd_hash` claim, which "MUST be computed over the US-ASCII bytes of the encoded SD-JWT", establishing commitment over the raw wire serialization without requiring intermediate parsing.

Similarly, {{RFC9449}} (Sections 4.2 and 11.8) embeds the `ath` claim (the SHA-256 hash of the ASCII access token) within the proof, relying on "the collision resistance of SHA-256" to reliably identify and bind the token.

Applying this principle to the opaque attestation wrapper requires the Verifier to compute a detached digest directly over the raw, serialized ciphertext bytes of the Evidence container (`ev_hash = Hash(enc_cmw)`) and embed this value within the signed Attestation Result.

Combining detached digests with digital signatures fulfills the {{RFC9530}} model (Sections 6.1–6.3), which specifies that combining content digests with digital signatures mitigates attacks where an on-path actor can "substitute it with a new digest value computed over manipulated representation data" and allows endpoints to verify data integrity across "multiple hops or system boundaries." This allows the Relying Party to independently hash the received `enc_cmw` on the wire and assert equality against the Verifier's signed statement without requiring decryption keys or parsing capabilities.

Embedding the detached digest (`ev_hash`) of the opaque Evidence wrapper into the Verifier's signed Attestation Result creates an unbroken cryptographic chain of custody across the three-party triangle. Just as the `ath` claim binds a proof to an access token in {{RFC9449}}, the `sd_hash` claim binds a Key Binding JWT to an SD-JWT envelope in {{RFC9901}}, and the `c_hash` claim binds an authorization code in OpenID Connect Core 1.0, embedding `ev_hash` within the Verifier's signed token mathematically locks the opaque payload sitting on the Relying Party's wire to the Verifier's appraisal statement, eliminating the substitution gap between the Attester-RP secure transport session and the transport-independent verification channel.

## Claim Definition {#claim-definition}

The `ev_hash` claim is defined for use in Attestation Results formatted as CBOR Web Tokens (CWT, {{RFC9052}}) or JSON Web Tokens (JWT). When expressed in an Entity Attestation Token (EAT, {{RFC9711}}), it provides cryptographic binding to an external payload.

The CDDL definition for the `ev_hash` claim value is:

~~~ cddl
ev_hash_claim = (
    ? ev_hash_key => ev_hash_value
)

ev_hash_key = (
    1001 / "ev_hash" ; Target claim label pending IANA assignment
)

ev_hash_value = [
    hash_alg: int / tstr, ; COSE/JOSE Algorithm Identifier
    digest: bstr          ; Raw output of Hash(enc_cmw)
]
~~~


# Protocol Processing Model {#processing-model}

## Attester Procedures {#proc-attester}

1. The Attester MUST assemble Evidence according to appraisal requirements established by the Verifier.
2. The Attester MUST encapsulate and encrypt the Evidence payload for the designated Verifier (producing `enc_cmw`).
3. The Attester MUST bind the in-flight session to the Evidence (e.g., embedding `session_binder_value` within the inner Evidence claims).
4. The Attester transmits `enc_cmw` to the Relying Party over the established transport session.

## Relying Party Forwarding Procedures {#proc-rp-forward}

Upon receiving `enc_cmw` from the Attester:

1. The Relying Party MUST NOT attempt to decrypt or alter `enc_cmw`.
2. The Relying Party MUST compute `local_digest = Hash(enc_cmw)` using an agreed cryptographic hash algorithm, executed over the raw, unparsed serialized bytes as received on the wire.
3. The Relying Party forwards `enc_cmw` to the Verifier.

## Verifier Appraisal Procedures {#proc-verifier}

Upon receiving `enc_cmw` from the Relying Party:

1. The Verifier MUST compute `computed_digest = Hash(enc_cmw)` over the unmodified byte sequence of the received Evidence ciphertext prior to parsing.
2. The Verifier decrypts and appraises the inner Evidence claims.
3. If appraisal succeeds, the Verifier MUST construct an Attestation Result containing:
   * The appraisal claims.
   * The embedded `session_binder_value`.
   * The `ev_hash` claim, populated with `computed_digest` and the algorithm identifier used.
4. The Verifier signs the Attestation Result and conveys it to the Relying Party.

## Relying Party Evaluation Procedures {#proc-rp-eval}

Upon receiving the Attestation Result from the Verifier:

1. The Relying Party MUST verify the digital signature and trust status of the Attestation Result.
2. The Relying Party MUST verify that the `session_binder_value` in the Attestation Result matches the active session with the Attester.
3. The Relying Party MUST extract the `ev_hash` claim from the Attestation Result.
4. The Relying Party MUST assert equality between `local_digest` and the digest contained in `ev_hash`:
   * If the values match, the Relying Party confirms payload correspondence.
   * If the values do not match, the Relying Party MUST reject the transaction and drop the connection.


# Cryptographic and Algorithm Considerations {#crypto-considerations}

To avoid algorithmic divergence:

* The hash algorithm used to compute `ev_hash` SHOULD be negotiated or declared via Verifier metadata.
* Algorithms MUST be cryptographically collision-resistant (e.g., SHA-256, SHA-384, or SHA-512). The use of MD5 or SHA-1 is strictly prohibited.
* Implementations SHOULD select a hash algorithm whose cryptographic strength is equal to or greater than the signature suite used to protect the Attestation Result.


# IANA Considerations {#iana}

## CWT Claim Registration

IANA is requested to register the following claim in the "CBOR Web Token (CWT) Claims" registry:

* **Claim Name:** `ev_hash`
* **Claim Description:** Evidence detached ciphertext digest binding
* **JWT Claim Name:** `ev_hash`
* **Claim Key:** TBD (Suggested: 1001)
* **Claim Value Type:** array
* **Change Controller:** IETF
* **Specification Document:** RFC-to-be [this document]

## JWT Claim Registration

IANA is requested to register the following claim in the "JSON Web Token (JWT) Claims" registry:

* **Claim Name:** `ev_hash`
* **Claim Description:** Evidence detached ciphertext digest binding
* **Change Controller:** IETF
* **Specification Document:** RFC-to-be [this document]


# Security Considerations {#security}

## Envelope Substitution vs. Replay Protection

The detached digest binding mechanism (`ev_hash`) directly prevents envelope substitution by establishing transitive cryptographic integrity between the ciphertext in transit on the Attester-RP link and the appraisal token generated by the Verifier. However, `ev_hash` alone does not provide temporal replay protection. Replay prevention depends strictly upon the Verifier validating freshness mechanisms (such as nonces or epoch counters) contained within the inner Evidence claims, coupled with the Relying Party validating that the `session_binder_value` echoes the current transport context.

## Verifier Hash Computation Boundary

The Verifier MUST compute `ev_hash` strictly over the exact byte stream of `enc_cmw` as received from the Relying Party. Re-encoding, canonicalizing, or formatting the ciphertext container before hashing will cause verification failure at the Relying Party.


--- back

# Acknowledgments
{:numbered="false"}

This specification builds upon concepts and security considerations established in RFC 9334 (RATS Architecture), RFC 9449 (DPoP), RFC 9530 (Digest Fields), and RFC 9901 (SD-JWT).
