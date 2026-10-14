# Signed governance checkpoint implementation plan

> **For agentic workers:** Use Superpowers subagent-driven development and test-driven development. Observe each intended red failure before production code, then obtain independent specification and quality review.

**Goal:** Bind one exact append-only history head and authority state to a provider signature, and verify a signed extension from a previously pinned head. This is the common checkpoint format for receipts, the product publisher and the independent observer.

**Approved shared design:** The user selected a standalone pure TypeScript authority library, an independently pulling observer, and nonblocking strict auditing. No release waits for an observer. The design is recorded in `docs/protocol-design.md` and the 1bridge D1–D4 shared design. This increment does not settle independent receipt transport.

**Approaches considered:** A bare Merkle root cannot authenticate its source or feed. A witness-countersigned checkpoint would couple normal completion to observer availability, contrary to the user decision. A provider-signed checkpoint checked against a separately pinned signer and retained prior head is the selected portable base; later observer replay and independent receipts supply stronger coverage.

## Ground truth

- `src/signatures.ts:22-29` domain-separates signed canonical records by purpose, and `src/signatures.ts:87-111` signs/verifies native P-256 signatures. Reuse it; do not add a second signature format.
- `src/history.ts:48-96` supplies RFC 9162 roots, inclusion and verification; its consistency functions are lower in the same file. Reuse `verifyConsistency` for extension checks.
- `src/hash.ts:3-6`, `:20-25` supply strict lowercase SHA-256 hash syntax and WebCrypto digest.
- `src/canonical.ts:94-113` supports canonical snapshots and exact parsing; check all protocol fields by descriptor before canonicalizing.
- The current library has no checkpoint export or test (`src/index.ts`, `test/` listing at plan time). The app and observer do not yet import this library.

## Journey and states

| Step | Caller | Before → after | Failure |
|---|---|---|---|
| Create initial head | Product publisher | Empty feed with size 0 and RFC empty root → signed size-0 checkpoint with `previous:null` | Malformed scope/root/key rejects |
| Append and sign | Product publisher | Prior signed head → signed larger head with predecessor statement hash | No product mutation here; invalid fields reject |
| Verify received head | Client/observer | Candidate + independently trusted signer key → authenticated statement | Wrong key, signer ID, shape, signature, scope or hash rejects |
| Verify extension | Client/observer | Pinned old head + new head + supplied RFC consistency proof → verified larger head | Rollback, fork, omitted predecessor, malformed proof or changed scope rejects |

No database, route, retention or network call participates. The caller pins the initial signer/feed independently; a signature returned by the same untrusted service is not by itself a trust anchor. Authority-map correctness and policy replay are later layers.

## Wire contract and changes

`GovernanceCheckpoint` is the exact object with data fields `version:1`, `feedId:Hash`, `size:number`, `historyRoot:Hash`, `authorityRoot:Hash`, `policyEpoch:number`, `signerKeyId:Hash`, `previous:Hash|null`. `feedId` is an opaque 32-byte lowercase-hex feed identifier. Size and epoch are nonnegative safe integers. Size zero requires `historyRoot = SHA256(empty)` and `previous = null`; positive size requires a hash predecessor. Other fields and accessors reject. The provider signing key is a P-256 pair supplied to `signCheckpoint`; signer ID must equal `signingKeyId(pair.publicKey)`. `SignedCheckpoint` is exactly `{statement:GovernanceCheckpoint, signature:string}` with a canonical 64-byte P-256 signature encoded as base64url. Sign with existing `signRecord('history.checkpoint', statement, key)`.

`checkpointHash(statement)` is SHA-256 of UTF-8 `1bridge.authority/v1/checkpoint-id\n` followed by canonical statement bytes, independent of randomized signature bytes. This is the predecessor/reference ID. It is not an external timestamp. `verifyCheckpoint(signed, trustedPublicKey)` returns false for malformed input or invalid signature and ensures the declared signer ID matches the trusted key. `verifyCheckpointExtension(oldSigned,newSigned,proof,trustedPublicKey)` verifies both signatures, same feed and signer, new size strictly larger, nondecreasing policy epoch, exact `previous = checkpointHash(old.statement)`, and RFC consistency of `(old.size,old.historyRoot)` to `(new.size,new.historyRoot)`. A signer rotation requires a later explicit authority transition API; this increment rejects it rather than silently trusting a new key. This function does not verify authorityRoot evolution or authorize the policy epoch change: full replay owns those checks.

Files: `src/checkpoint.ts` owns this wire/signature/extension contract; `src/index.ts` exports public names; `test/checkpoint.test.ts` covers domain, shape, bounds and extension; `docs/checkpoint-profile.md` states construction and trust limits. No dependency or directory convention is introduced.

## Proposed names

| Name | Responsibility | Name strain / decision |
|---|---|---|
| `GovernanceCheckpoint` | Exact unsigned statement | One concept; keep |
| `SignedCheckpoint` | Statement plus provider signature | One concept; keep |
| `checkpointHash` | Stable statement reference independent of signature | One concept; keep |
| `signCheckpoint` | Validate/snapshot and sign one statement | One operation; keep |
| `verifyCheckpoint` | Validate one statement/signature against a pinned public key | One operation; keep |
| `verifyCheckpointExtension` | Check signed monotonic log extension | One operation; keep; the history relation is indivisible here |

Private helper names, if needed: `snapshotStatement` for exact descriptor/field validation, `snapshotSignedCheckpoint` for exact signed envelope. Avoid action or receipt concerns in this module.

## Test plan

| Behavior | Layer | Assertion and red/mutation check |
|---|---|---|
| Initial head format and statement ID | Unit | Missing export first fails; independent Node SHA-256 of exact domain+canonical bytes matches; change domain prefix and see failure |
| Sign/verify | Unit | Own pair succeeds; wrong key/purpose/modified root/size/scope/signature fails; mutating inputs during async signing never changes returned signed statement |
| Strict wire profile | Unit | Extra/missing/accessor/symbol fields, malformed hashes, noncanonical signature, negative/fractional/unsafe/negative-zero size or epoch, inconsistent zero/nonzero predecessor reject; acceptance must not invoke untrusted getters |
| History extension | Unit | Real roots/consistency proofs for 0→1, 1→2, 2→3 and irregular sizes pass; rollback, equal-size mutation, changed feed or signer, wrong predecessor/proof, rewritten prefix reject; deliberately disable predecessor or consistency comparison to prove tests fail |
| Browser/Node | Compiled package smoke | Node and selected Chromium/Firefox/WebKit sign/verify on exact exported build; complete browser suite remains separate readiness work |

## Principles, smells and verification

SRP: checkpoint authenticity/extension only. DRY: existing signer, canonical encoder and RFC history verifier remain authoritative. KISS: exact fixed profile rather than options, clock claims or witness callbacks. Boy Scout: scoped cleanup only, behavior-preserving edits separate if nontrivial. `verifyCheckpoint` only confirms provider-signed state under a trusted key; it does not prove the map or every transition is authorized. New authority signer rotation and durable publication need later explicit tests.

Run focused red/green/mutation tests, full `pnpm test`, `pnpm typecheck`, `pnpm build`, built ESM/browser smokes, `git diff --check`, and scoped smell review. The app lint/typecheck:gate/test/integration/E2E gates apply when app source changes; no app source change is authorized by this increment.

## Execution and review record

- Implemented in focused commit `f44e551`. The first run failed on four missing exports across 18 tests. Deliberate mutations of the checkpoint-ID domain, predecessor comparison, consistency comparison and getter guard each failed a targeted test before restoration.
- Fresh independent specification review passed; fresh independent quality review accepted without actionable findings. Both reviews identified the immediate-predecessor catch-up obligation, now explicit in `docs/checkpoint-profile.md` and the observer architecture.
- Parent verification after review: `pnpm test` passed 418 tests in 8 files, `pnpm typecheck`, `pnpm build`, and `git diff --check` passed. A selected built-package browser smoke passed 27 checks each in Chromium 149.0.7827.55, Firefox 151.0 and WebKit 26.5, including Node→browser checkpoint verification, browser checkpoint extension and browser→Node verification. This does not run the full unit suite in browsers.
- No app source/schema/dependency changed. Database durability, receipt binding, authority replay and observer backlog remain required; this commit does not pass the full library readiness gate.
