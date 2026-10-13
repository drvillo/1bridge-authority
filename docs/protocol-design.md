# Authority and observation protocol blueprint

Status: planned layers beyond the history foundation. These records are not yet implemented exports. Nothing in this document claims full-library readiness, cryptographic review or deployed 1bridge support.

## Shared ownership

The library owns proof/encoding/signature verification; the product owns application action semantics and transaction orchestration; the independent observer owns retained state, replay, receipt reconciliation and signed coverage. The history module alone provides neither authorization nor global omission detection.

All releases continue while the observer is offline, including strict Enterprise/Government auditing. Strictness controls mandatory checks/retention/reporting, never release waiting. Independent receipt replication requires a configured archive; its transport remains a planned interface.

## Wire and signature boundaries

Use versioned canonical JSON with an explicitly specified subset: strings, booleans, null, safe integers, arrays and plain objects; sorted object keys; no undefined, nonfinite values, fractional numbers, lone surrogates or ambiguous serialized forms. A parser accepting serialized records requires canonical re-encoding equality, so duplicate-key or alternate encodings cannot silently change signed interpretation.

Hash references are lowercase 32-byte SHA-256 hex. Encode binary signature/key values with canonical base64url and fixed algorithm profiles. Sign domain-separated bytes for each record kind; an approval signature must not verify as a policy-reset signature merely because payloads match.

Native ECDSA P-256/SHA-256 signing uses WebCrypto's fixed 64-byte IEEE-P1363 representation. Public-key ID is a domain-separated fingerprint of the exact accepted public key encoding. Enrollment rejects wrong curve, malformed/off-curve keys and wrong-purpose signatures. App encryption keys remain X25519; never reinterpret them as signing keys.

## Root and delegation

A separately customer-held AuthorityAnchor fixes protocol version, workspace/log identity, customer-root public key, initial delegated actor-signing keys/capabilities, independent observer configuration when chosen, policy epoch and recovery-authority public keys. The initial root pin comes from independently authenticated configuration/ceremony, not a replacement key returned by the provider.

Delegations bind exact subject/key/version, scope, permitted actions and validity. Historical replay evaluates authorization at that revision, not mutable present-day server role fields. Recovery-authority resets supersede exposed paths with explicit epoch/predecessor binding; compromised online actors cannot authorize their own independent recovery.

The product supplies role/action semantics to a common typed verifier instead of hardcoding a second permission system in each route. Baseline access controls remain operationally enforced; signed authority supplies independent evidence.

## Ordered map and chronological history

Use a deterministic balanced ordered map over unique scoped subjects, including signed key/delegation/revocation state. Hash node domain, subject, record commitment and child roots. Presence reveals a selected record/path; absence proves an ordered search terminates at an authenticated empty boundary. Enforce ordering, uniqueness and exact path direction; arbitrary leaf membership is insufficient for absence/currentness.

Each authority revision commits expected predecessor and resulting map root into the RFC 9162 chronological log. The observer reconstructs/compares both. The initial snapshot method rebuilds O(N); no incremental O(log N) update claim. Complete canonical data is retained so cached nodes can be reconstructed.

## Attributable action and completion

SignedAction binds protocol version, workspace/log, operation ID, actor signing-key/version/device stream, action class, exact authority/policy revision, intended event/content/result commitments, expected predecessor and previous VERIFIED completion evidence. Rejected/canceled/abandoned attempts do not advance the completed-action chain.

CompletionReceipt binds exact action/event hash, result commitment, log leaf index, provider-signed checkpoint and inclusion proof. Receipt status distinguishes integrated evidence from a future integration promise; initial release contract requires locally integrated evidence. Product mutation/journal/replay result are atomic, with a short expected-head update. No network call runs under that database transaction.

Clients validate and retain receipts before accepting protocol completion, keep device-scoped history pins, and include prior receipts within later signed actions. Input retries replay the same result or reject changed canonical payloads. New devices import authenticated state or bootstrap independently rather than silently resetting trust from the provider.

## Observer coverage

Checkpoint discovery fixes a target head. Bounded contiguous range retrieval, signature/authorization/map replay and exact consistency/inclusion checks advance a durable independent frontier. Partial progress never yields full-head certification. Polling resumes after arbitrary outages and redelivery.

ObservationStatement binds observer identity, exact verified head/frontier, signed policy revision, known independent-receipt reconciliation scope, check time and unresolved coverage/finding references. Reporting scope is explicit: an observer cannot certify that its sample includes every operation worldwide. Gaps remain durable; successful unrelated polls cannot clear them.

The independent archive option supplies client-originated, asynchronously queued copies. An ingestion endpoint verifies customer-scoped authorization and receipt bounds; monitoring still pulls 1bridge. Access to proof material and permission to add archival evidence are distinct. Receipt-store transport is not yet implemented; verification contracts remain the same.

## Audience evidence and access tokens

Approvals remain attributable. Private evidence uses independently salted commitments and encrypted bodies; selected openings reveal only required material. An observer validates only the policy material available to its configured audience. Opaque identifiers and blind tokens do not make revealed approvals or network metadata anonymous.

ProofAccessToken follows RFC 9474 ordinary RSA blind signatures with randomized preparation. Use a dedicated, customer-certified shared capability/expiry/audience issuer-key cohort; unique per-user keys are forbidden by the intended privacy profile. Token randomness is independently generated and one-use redemption is atomic. The signer never blindly approves arbitrary governance data.

Private RSA operations use the server's native cryptographic primitive under a separate Node entry point. No JavaScript private exponent arithmetic or production-security claim from functional tests. Client public blinding/unblinding/PSS encoding must match exact RFC vectors; native final RSA-PSS verification and adversarial keys/outputs are required.

## Persistence interfaces

Core cryptography is storage-free. A server adapter supports the app's existing Prisma transaction and qualified private authority schema. Store immutable canonical events, map state, tree/head data and replayable receipts with expected-head acceptance. Queues are wake-ups, not independent custody or sole ordering.

Observer persistence is independently administered Postgres, also compatible with Supabase. Durable cursors, retained roots/receipts, unresolved ranges/dependencies and signed findings survive restarts/races. No provider service-role credential enters the observer deployment.

## Readiness gates and research

Remaining library increments require canonical/signature conformance, root/delegation/revocation/recovery replay, ordered-map presence/absence, receipts/pins/coverage, audience evidence, blind-access vectors/replay, storage concurrency/crash tests and actual browser/Node imports. Observer fixtures and real Postgres/Vercel setup must pass before app edits.

Trace CIRT (NDSS 2014), RFC 9162 history, SUNDR (OSDI 2004) fork reasoning, CATS (FAST 2007) accountability, and RFC 9474/Privacy Pass token privacy to exact functions/tests/results. Adaptations and trust/delivery assumptions remain explicit; passing tests is not formal verification of the complete composition.
