# Frozen governance vector implementation plan

> For implementation: use the Superpowers test-driven workflow task by task. The user has already requested continued implementation, so execute inline. This plan lives in the existing `docs/` convention; it introduces no planning directory.

**Goal:** Give the public authority package and the independent observer one byte-for-byte shared governance history fixture before any 1Bridge app source integration.

**Architecture:** Generate one signed mixed history from the observer's existing fixture builder, then commit only its public canonical signed anchor, ordered checkpoints and leaves, and expected replay snapshot. Both repositories retain an identical copy with a fixed SHA-256 file digest; the library replays it directly, while the observer serves it over the existing test HTTP publisher and verifies it through its real pull client. No signing private key is committed.

**Tech stack:** TypeScript, Vitest, the existing authority package, Node SHA-256 and canonical base64url; no new runtime dependency.

**Implementation record:** The public vector has SHA-256 `b648945a00e00ea998b8f6a070d620a4ecd2ce05882d66c17b65ca13767d18b5`, seven leaves and eight checkpoints. It contains no signing private keys. The fixed hash is asserted in both repositories. The authority test replays the exact retained prefix; the observer test serves the same bytes over HTTP and replays them through the pull client. A substituted last leaf is rejected. A future protocol change must create a new versioned vector rather than silently replacing this one.

---

## Ground truth

- `1bridge-observer/test/governance-source-fixture.ts:83-135` creates the pinned anchor, two actors, policy and provider-key rotation with a prior-receipt action. Its server currently consumes `signedAnchor`, `leaves`, `checkpoints` and `alternateLastLeaf` at `:145-201`.
- `1bridge-authority/src/replay.ts:285` accepts a complete ordered prefix and returns `GovernanceReplaySnapshot`; `1bridge-observer/src/lib/verify-source.ts:29-72` pulls and replays a fixed source head but has no frozen cross-repo test input.
- Unverified until tests: exact serialized fixture digest, browser portability of this frozen fixture, and whether future app adapters emit the same bytes.

## Journey and states

| Step | Caller | Route/library | Durable state | Failure |
|---|---|---|---|---|
| Freeze | Test fixture generator, once | Existing `buildGovernanceSource` | Public signed bytes committed in both repos | Private key or noncanonical/changed vector rejected in review/test |
| Verify portable history | Authority test | `replayGovernanceHistory` | No DB mutation | Wrong pin, leaf or checkpoint fails |
| Verify pulled history | Observer test HTTP publisher | Existing source GET routes and `verifySourceTarget` | No DB mutation | Missing/changed page fails |

## Changes and proposed names

| Name/path | Responsibility | Name-strain decision |
|---|---|---|
| `test/fixtures/governance-v1.json` in authority; `test/governance-v1.json` in observer | Identical fixed public vector, including encoded anchor/checkpoints/leaves and expected snapshot | Use each repository's existing test directory layout; no app convention |
| `test/frozen-governance-vector.test.ts` in both repos | Consume the fixed bytes and assert exact digest plus replay outcome | One test responsibility per repo; no generic fixture framework |
| `startGovernanceSource` input type | Accept the minimal public-history fields already used by the test server | Narrow an existing type, no new publisher route |

## Test plan

1. Add the authority test to load `test/fixtures/governance-v1.json`; run it before creating the file and observe a missing-fixture failure. Generate one vector from the existing observer fixture. Assert exactly eight checkpoints, seven leaves, the independently pinned feed ID and the full expected replay snapshot. A changed leaf or checkpoint must fail replay.
2. Add the observer test to load the same JSON and compare the fixed file SHA-256 digest with the authority copy. Serve its exact bytes through `startGovernanceSource`; run before copying the file to observe a missing-fixture failure, then copy the file and verify the real HTTP pull result. Corrupt a copied leaf and observe failure.
3. Run `pnpm test`, `pnpm typecheck`, `pnpm build` in authority; run `pnpm test`, `pnpm lint`, `pnpm typecheck`, `pnpm build` and the existing SQL test in observer. Check both file digests from the shell, `git diff --check`, and push both public commits only after gates pass.

## Principles and Boy Scout scope

SRP: the authority repo owns canonical verification and the observer owns transport; the vector is shared evidence, not a shared test harness. DRY: two copied public JSON files are intentional for offline CI interoperability and fixed-hash equality. KISS/YAGNI: no signing-key serialization, new generator dependency, app route, database claim or new algorithm. Keep cleanup to touched fixture and test files. The vector proves cross-repo byte compatibility, not independent cryptographic correctness, freshness, production persistence or suppression detection.
