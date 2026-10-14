# 1bridge authority

Pure TypeScript primitives for workspace-scoped authority and independently checkable governance evidence. Experimental development; no production audit or formal verification is claimed.

Implemented primitives: RFC 9162 Merkle history and append frontier, deterministic ordered-map presence/absence proofs, restricted canonical JSON and base64url, purpose-bound native P-256 signatures, audience-scoped salted evidence commitments, signed governance checkpoints, pinned customer-root authority replay, exact recipient-key commitments and app-UUID mappings, actor-signed governance actions, inclusion receipts, complete-prefix and process-local bounded-page mixed-history replay, source-scoped signed observer reports, and RFC 9474 blind proof-access tokens. Private evidence-body disclosure, durable storage and product/observer integration remain subsequent increments. This experimental package is not ready for 1bridge integration.

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

`signObserverReport` binds a supplied replay snapshot to its exact signed checkpoint and a separately operated observer key. `verifyObserverReport` checks report syntax, pin/feed scope and the observer's signature; it does not replay the history or create an independent receipt archive. See [the report profile](docs/observer-report-profile.md) for precise claims and limits.

See the profile documents under `docs/` for construction, test coverage and limits. Package tests, typecheck and build pass on Node 26.5; selected compiled-module browser smokes exercised pinned authority replay, ID mapping and blind-token round trips in Chromium, Firefox and WebKit. These are not full browser policy/workflow evaluations or a formal security proof. Product issuance eligibility, cohort certification, atomic one-use redemption and meaningful database-effect openings are not implemented by this library.

`test/fixtures/governance-v1.json` is a fixed public cross-repository vector of one mixed authority/action history. Its exact SHA-256 is pinned by both this package's replay test and the observer's HTTP pull test; see [the vector plan](docs/cross-repo-governance-vector-plan.md). It contains signed public artifacts, not private signing keys. It proves those two consumers agree on the same bytes, not that the app publishes them yet.
