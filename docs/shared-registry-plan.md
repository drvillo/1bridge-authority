# Shared registry implementation plan

> For agentic workers: use the Superpowers test-driven-development and executing-plans workflows task by task.

**Goal:** Let one independently pinned observer discover and verify every advertised 1Bridge governance feed without customer-specific configuration.

**Architecture:** A global, signed append-only Merkle registry contains pseudonymous feed anchors and signed feed heads. Each feed retains the existing authority/action replay contract. The registry authenticates discovery and publication order; per-feed replay validates authorization. Neither layer proves that an unpublished event existed, nor that an effect commitment matches a private database mutation.

**Tech stack:** Pure TypeScript, WebCrypto P-256/SHA-256, canonical JSON, existing Merkle primitives and Vitest; no new dependency.

## Ground truth and boundaries

- The library already implements RFC 9162-style inclusion and consistency verification in `src/history.ts`, signed per-feed checkpoints in `src/checkpoint.ts`, and authority/action replay in `src/replay.ts`.
- `src/authority-lifecycle.ts` contains the dual-signed feed anchor, so a registry registration can carry existing enrollment evidence. A provider-created anchor still does not establish a named real-world organization; customers pin their own anchor.
- The observer currently configures one `FEED_ID`, `ANCHOR_PIN`, and `SIGNED_ANCHOR` in `1bridge-observer/src/lib/config.ts`; a global registry and a new observer protocol are needed before claiming shared coverage.
- One global publisher key is pinned out of band by the observer. Version 1 does not rotate this key in place; a replacement needs an explicit, publicly documented trust-anchor transition.
- A registry head is publication evidence, not feed validation. Only the observer's successful replay can call it verified.

## Registry wire contract

- `RegistryEntry` is a canonical JSON union: `feed_anchor` carries an index, pseudonymous `feedId`, `anchorPin`, and exact signed authority anchor; `feed_head` carries an index, `feedId`, and exact signed feed checkpoint. Index equals the Merkle leaf index. The registration entry precedes the first head for that feed; a feed ID is registered once. A head must increase the feed size or point to the same exact checkpoint only as an idempotent retry outside the tree. The observer verifies all checkpoint transitions using the existing per-feed replay, not merely this registry syntax.
- `RegistryCheckpoint` contains version, size, Merkle root, publisher key ID and hash of the previous signed checkpoint statement. Size zero uses the empty root and no predecessor. Every nonempty successor points to the prior checkpoint statement hash. The checkpoint's signature purpose is separate from feed checkpoints.
- A fixed-target source API supplies the signed registry checkpoint, every missed immediate-predecessor checkpoint, contiguous entry pages and consistency proof for each accepted transition to the target. Canonical bytes are what the observer hashes and retains. The observer never advances its accepted registry head past entries whose syntax and append-only proof pass. Per-feed heads may remain pending until their feed replay succeeds.
- Signed observer aggregate coverage names the accepted registry checkpoint and commits separate Merkle roots/counts of sorted verified and pending feed-status records plus retained findings. Each status record contains feed ID, anchor pin, advertised head hash (or null) and status. The observer publishes/query-serves these records with compact inclusion proofs; a customer verifies its own status against independently expected feed ID and anchor pin without embedding every feed ID in the signed statement. This report must not imply that every advertised feed is verified when one is pending. Detailed per-feed reports remain independently verifiable. A status proof confirms inclusion in the observer's signed set; independently checking whether the sets exhaust the registry requires the full registry evidence.
- Public envelope disclosure: pseudonymous feed IDs, public signing keys and binding actions, action classes, causal hashes and publication cadence. No customer name, plaintext documents, recipient contact, evidence opening or customer secret appears in registry entries.

## Files and proposed names

| Path | Responsibility | Proposed names / name strain |
|---|---|---|
| `src/registry.ts` | Validate and hash registry entries; sign/verify registry checkpoint; verify extension | `registryEntryBytes`, `registryCheckpointHash`, `signRegistryCheckpoint`, `verifyRegistryCheckpoint`, `verifyRegistryExtension`; each has one protocol purpose. |
| `src/registry-replay.ts` | Stateful replay of contiguous entries and feed registrations | `createRegistryReplaySession`, `appendRegistryEntries`, `registryReplaySnapshot`; no conditional compound names. |
| `src/observer-aggregate.ts` | Sign/verify exactly scoped aggregate coverage | `signAggregateReport`, `verifyAggregateReport`; separate from existing per-feed report. |
| `src/index.ts` | Export the versioned public API | No new helper. |
| `test/registry.test.ts`, `test/registry-replay.test.ts`, `test/observer-aggregate.test.ts` | Test protocol invariants and adversarial substitutions | Test names state domain outcomes. |
| `test/fixtures/shared-registry-v1.json` | Frozen cross-repository bytes and expected hashes | No executable logic. |

## Tasks

### 1. Registry checkpoint and leaf format

- [x] Write tests that build a signed zero-size checkpoint, append a registration and a head, and independently calculate the Merkle root from exact canonical entry bytes. Assert signature and inclusion/consistency success.
- [x] Run `pnpm exec vitest run test/registry.test.ts` and see failures for the missing registry API.
- [x] Implement entry validation, canonical encoding, statement hash and checkpoint signing/verification, reusing `history.ts`, `signatures.ts`, `canonical.ts`, and `authority-lifecycle.ts`.
- [x] Add tests for wrong feed ID, extra fields, accessors, wrong publisher key, shorter tree and invalid consistency proof. Exact pin/signature validation is tested at registry replay rather than the synchronous entry encoder.
- [x] Run focused test, typecheck and build. Commit follows the complete library gate below.

### 2. Stateful registry replay

- [x] Write failing tests for contiguous page catch-up after an offline interval, duplicate registration, head before registration, forged anchor pin, feed-size rollback and gap.
- [x] Run `pnpm exec vitest run test/registry-replay.test.ts`; failures identified the absent replay API.
- [x] Implement a bounded replay session that retains the accepted registry head and per-feed anchor/head pins, verifies append-only extension, and returns an immutable snapshot. Persistent observer cursor integration remains in the observer repo.
- [x] Run focused tests, typecheck and build. Commit follows the complete library gate below.

### 3. Aggregate witness statement

- [x] Write failing tests for a two-feed report, one verified and one pending; verify the statement distinguishes published coverage from validated feed coverage.
- [x] Add tamper tests for changed feed head, omitted pending count, wrong registry snapshot, wrong signing key, duplicate verified feed and getter-backed arrays. Additional cross-repo adversarial tests remain in Task 4.
- [x] Implement a versioned signed report with exact schema and canonical digest. Retain existing per-feed report semantics and signatures.
- [x] Run focused tests and typecheck. Commit follows the complete library gate below.

### 4. Cross-repository fixture and publication gate

- [x] Freeze a vector with two anchors, two signed genesis heads, an offline backlog and adversarial omitted/substituted leaves. The observer must consume the same bytes without regenerating expected values from its own implementation. A later invalid feed transition remains an observer cross-repo test.
- [x] Freeze and cross-check an Enterprise recovery-custody/reset vector separately from the shared-registry fixture. It contains recovery-key-authorized reset, fresh routine/recovery possession and a rejected old-routine revision; no private key enters the public fixture. The observer's copied vector passed its focused test against the previously pinned authority API.
- [x] Run `pnpm test`, `pnpm typecheck`, `pnpm build`; review changed-file smells and protocol docs. The registry/recovery code received a separate read-only review with no remaining high-impact finding. Pin the exact commit in the observer after publication.
- [ ] Publish the public repository/commit only after the tested API and fixture are stable; CI must pass on the pushed commit.

## Principles, migration and verification

The registry is a proof index over one canonical product audit, not a second business audit. Domain events are added only in the application phase. The package is additive: existing per-feed APIs and fixtures remain valid. A registry leaf cannot silently re-register a feed or claim a private action occurred. The no-observer deployment remains operational; only coverage freshness changes. Run all package gates and observer cross-repo tests before any app source, schema or package edit.
