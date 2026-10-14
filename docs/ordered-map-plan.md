# Ordered authority map implementation plan

> Use Superpowers test-driven development and subagent-driven development. Each implementation task starts with a failing test, ends with a focused commit, and receives specification then quality review.

**Goal:** Provide a compact proof of a scoped authority key's current binding or absence at a trusted map root.

**Architecture:** The library builds a deterministic balanced binary search tree from a sorted snapshot of opaque 32-byte keys and 32-byte value commitments. A proof follows the unique search path to either a matching node or an authenticated empty child. The observer later reconstructs the map from the chronological history, verifies sorting and uniqueness, and compares its root with signed checkpoints.

**Tech stack:** TypeScript 5.9, WebCrypto SHA-256, Vitest 3.2; zero runtime dependencies.

## Ground truth

- `src/hash.ts:5` accepts lowercase 64-character hashes, and `src/history.ts:19` snapshots input before asynchronous hashing.
- `src/index.ts:1` exports the portable cryptographic API; `package.json` has no runtime dependencies.
- `docs/protocol-design.md` specifies ordered-map presence and absence with empty-boundary paths, and admits snapshot rebuilding costs O(N).
- Unverified until this increment: any authority map root or proof can be generated or checked by the package.

## Journey and states

| Step | Caller | State before → after | Failure state |
|---|---|---|---|
| Commit bindings | Publisher passes sorted unique opaque keys and value commitments | Canonical snapshot → map root | Duplicate, unordered, malformed key/value rejects |
| Verify a binding | Client receives one path under a pinned root | Unverified → valid presence | Wrong key/value/path/root rejects |
| Verify absence | Client receives search path ending in an empty child | Unverified → valid absence | Missing, reversed or wrong-direction ancestor rejects |
| Replay | Observer reconstructs sorted snapshot | Journal state → recomputed root | Root mismatch or invalid ordering becomes finding |

No product route, database state or client pin is modified in this increment. Those are later integrations.

## Changes and files

- `src/ordered-map.ts`: root, proof generation and verification for the single deterministic tree profile.
- `src/index.ts`: export the public map API and proof types.
- `test/ordered-map.test.ts`: independent SHA-256 node oracle, round trips, malformed proofs, ordering, async mutation and known vectors.
- `docs/ordered-map-profile.md`: exact hash bytes, tree shape, proof path order and trust limits after tests pass.

## Wire and hash contract

`MapEntry` has `key` and `valueHash`, each exactly 64 lowercase hex characters. Keys are opaque commitments to scoped subject identifiers; callers must not put guessable identifiers here. Sorted means strict lexicographic ascending by these fixed-width lowercase hex strings. The constructor rejects duplicates and out-of-order input instead of silently sorting it. It snapshots every entry synchronously before its first `await`.

The empty child/root is `SHA256(0x03)`. A nonempty node is `SHA256(0x02 || key[32] || valueHash[32] || leftRoot[32] || rightRoot[32])`. `0x02` and `0x03` are distinct from RFC 9162's history prefixes `0x00` and `0x01`. For N entries, index `floor(N/2)` is the root; recursively apply the same rule to each half. This builds O(N) nodes and a proof of O(log N) hashes. This does not claim O(log N) update cost.

`orderedMapProof(entries, key)` returns either `{kind:'present', key, valueHash, left, right, path}` or `{kind:'absent', path}`. Each path step is `{key, valueHash, sibling, direction}` in **bottom-up** order. `direction:'left'` means the searched subtree is the ancestor's left child, hence `queryKey < ancestorKey`; `right` means `queryKey > ancestorKey`. `verifyOrderedMapProof(key, proof, root)` recomputes the root and checks the search inequalities, including the target key for presence; malformed input returns false. The verifier establishes a path under the supplied root, not that the supplied root is the latest customer-authorized state. Observer replay must validate the complete ordered snapshot before claiming map validity.

## Proposed names

| Name | Responsibility | Name strain / decision |
|---|---|---|
| `orderedMapRoot` | Commit one sorted snapshot | Single concept; keep |
| `orderedMapProof` | Produce the unique search path | Single concept; keep |
| `verifyOrderedMapProof` | Check a path against a trusted root | Single concept; keep |
| `MapEntry`, `MapProof`, `MapPathStep` | Transport exact typed commitments | Single role each; keep |

## Test plan and steps

1. **Red:** Add `test/ordered-map.test.ts` with an independent Node `createHash` oracle for empty and hand-built one/two/three-node trees. Import the desired exports. Run `pnpm exec vitest run test/ordered-map.test.ts`; expect failure because the map export/module does not exist.
2. **Green:** Implement exact domain-separated hashing and deterministic midpoint root. Check `orderedMapRoot([])` and oracle roots for 1, 2, 3, 7 entries. Confirm actual assertion failures precede each newly implemented behavior.
3. **Red:** Add producer/verifier tests for every present key and every gap including first, last and empty map, sizes 0…33 and 63/64/65. Assert wrong value, root, key, direction, sibling, order and truncation reject. Run the focused test and observe the missing-proof failure.
4. **Green:** Implement bottom-up paths and verifier with explicit structure, canonical hash, direction and key-order checks. Snapshot input and proof fields before the first asynchronous hash. Reject path length over 53 and malformed/cyclic objects without throwing from the verifier.
5. **Red/green:** Add a mutation test that changes a caller-owned entry or proof while hashing is awaiting; both results must reflect the pre-await snapshot. Add malformed input tests for duplicate/out-of-order keys, uppercase hashes, sparse arrays and accessors, then satisfy them. Break one invariant deliberately, observe a test fail, restore it.
6. **Finish:** Write `docs/ordered-map-profile.md`, run `pnpm test`, `pnpm typecheck`, `pnpm build`, inspect the built ESM import and review `git diff --check`. Commit only this increment on `codex/authority-foundation`. Follow with a separate spec review and quality review.

## Principles, smells and verification

One map module owns its wire profile. The observer will own replay and the product will own persistence; neither is smuggled into this portable package. Keep `orderedMapRoot` and `orderedMapProof` over one internal tree builder rather than duplicate hash rules. The implementation should make the search path visible without adding a generalized tree framework. Review names and touched-file complexity before commit. Verify the targeted red/green record, full package tests, typecheck/build, ESM smoke, mutation check, and a separate specification and quality review.

## Execution record, 2026-10-14

Implementation commit `3a14e1c` contains the map module, 82 map tests, index exports and exact-byte profile. The implementer reported observed missing-export red tests, a nonenumerable-field red test and two deliberate inequality mutations caught by tests. Those historical terminal runs are not independently reconstructible from the combined commit, so reviewers marked the red history as implementer-reported. Both independent reviews accepted the resulting source and tests. The quality reviewer additionally compared 2,340 absence paths against an independent ancestor-order oracle without a mismatch. Package test, typecheck, build, built ESM smoke and diff checks passed in those reviews. This increment does not certify a signed latest root, full authority replay, observer operation or app integration.
