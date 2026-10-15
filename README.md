# 1bridge authority

Pure TypeScript primitives for workspace-scoped authority and independently checkable governance evidence. Experimental development; no production audit or formal verification is claimed.

Implemented primitives: RFC 9162 Merkle history and append frontier, deterministic ordered-map presence/absence proofs, restricted canonical JSON and base64url, purpose-bound native P-256 signatures, audience-scoped salted evidence commitments, signed governance checkpoints, pinned customer-root authority replay, exact recipient-key commitments and app-UUID mappings, actor-signed governance actions, inclusion receipts, complete-prefix and process-local bounded-page mixed-history replay, a signed multi-feed registry with process-local replay, scoped per-feed and aggregate observer reports, and RFC 9474 blind proof-access tokens. Private evidence-body disclosure, durable shared-observer storage and product integration remain subsequent increments. This experimental package is not ready for 1bridge integration.

## Development

Use Node 22 or later and pnpm 10.29.3:

```sh
pnpm install --frozen-lockfile
pnpm test
pnpm typecheck
pnpm build
```

Git consumers must pin an immutable commit and allow this first-party package's `prepare` build under pnpm 10. In the consumer's `pnpm-workspace.yaml`:

```yaml
onlyBuiltDependencies:
  - '@drvillo/1bridge-authority'
```

Then install `github:drvillo/1bridge-authority#<reviewed-commit>`. A fresh consumer install without the allowlist refuses the build; a local Git-commit install with the allowlist loaded both the root and Node-only `./server` exports. This is package-consumption guidance, not product-integration readiness.

Core modules use native WebCrypto with no runtime dependencies. `replayGovernanceHistory` authenticates a supplied complete prefix under an independently obtained customer pin and caps its input at 10,000 leaves and 32 MiB. `createGovernanceReplaySession` accepts bounded pages beyond that input ceiling in one process; it cannot resume securely from an untrusted serialized state after a serverless restart. See `docs/streaming-replay-profile.md` for tested feed shapes and capacity limits. Neither API proves that a database effect occurred, that the selected head is globally fresh, or that an entirely hidden history does not exist. A later same-key action or an independently retained receipt can expose some suppressed events; the scope and limits are in `docs/mixed-history-replay-profile.md`.

`verifyGovernanceHistoryExport(retainedCheckpoint, candidateHistory)` verifies the v1 customer export format entirely offline. A consumer can parse two locally saved JSON files and call it without a 1Bridge API, database or observer connection:

```ts
import { readFileSync } from 'node:fs'
import { verifyGovernanceHistoryExport } from '@drvillo/1bridge-authority'

const retained = JSON.parse(readFileSync('retained-checkpoint.json', 'utf8'))
const candidate = JSON.parse(readFileSync('candidate-history.json', 'utf8'))
const result = await verifyGovernanceHistoryExport(retained, candidate)
console.log(result.feedId, result.checkpointHash, result.retainedCheckpointHash)
```

The checkpoint and anchor pin must have been saved or authenticated outside the publisher before the later candidate is supplied. The verifier replays at most 50,000 leaves and 64 MiB of encoded history in bounded pages, verifies every historical authority/action and publisher checkpoint, and requires the exact retained signed checkpoint in the accepted chain. It cannot detect a coherent tail that nobody independently retained or witnessed, and callers should cap JSON file size before parsing untrusted files.

`signObserverReport` binds a supplied replay snapshot to its exact signed checkpoint and a separately operated observer key. `verifyObserverReport` checks report syntax, pin/feed scope and the observer's signature; it does not replay the history or create an independent receipt archive. See [the report profile](docs/observer-report-profile.md) for precise claims and limits.

`createRegistryReplaySession` checks a signed global append-only feed registry under one independently pinned publisher key. It verifies dual-signed feed registrations and advertised-head ordering, while the separate per-feed replay must validate each advertised head's authority/action history. `signAggregateReport` distinguishes fully replayed advertised heads from pending feeds; `aggregateFeedStatusProof` and `verifyAggregateFeedStatus` provide a compact proof for one explicit status. The status verifier requires the customer's independently expected feed ID and anchor pin to prevent substituting another feed's valid proof. `verifyAggregateReport` authenticates the observer's statement and signed registry checkpoint, but does not independently reconstruct every feed. See [the shared-registry plan](docs/shared-registry-plan.md) and [protocol design](docs/protocol-design.md). The frozen [two-feed vector](test/fixtures/shared-registry-v1.json) contains only public artifacts and is intended for the observer's cross-repository tests.

See the profile documents under `docs/` for construction, test coverage and limits. Package tests, typecheck and build pass on Node 26.5; selected compiled-module browser smokes exercised pinned authority replay, ID mapping and blind-token round trips in Chromium, Firefox and WebKit. These are not full browser policy/workflow evaluations or a formal security proof. Product issuance eligibility, cohort certification, atomic one-use redemption and meaningful database-effect openings are not implemented by this library.

`test/fixtures/governance-v1.json` is a fixed public cross-repository vector of one mixed authority/action history. Its exact SHA-256 is pinned by both this package's replay test and the observer's HTTP pull test; see [the vector plan](docs/cross-repo-governance-vector-plan.md). It contains signed public artifacts, not private signing keys. It proves those two consumers agree on the same bytes, not that the app publishes them yet.

`test/fixtures/recovery-custody-v1.json` freezes public anchor and revision records for an Enterprise recovery-key-authorized reset. Both repositories verify that a subsequently signed revision from the former routine root is rejected. It contains no private signing keys and does not prescribe how an Enterprise administrator stores the recovery key.
