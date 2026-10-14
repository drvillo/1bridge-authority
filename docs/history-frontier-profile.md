# Append-only history frontier profile

The portable frontier updates an RFC 9162 SHA-256 history root after one new leaf without revisiting earlier leaves. The public API is:

```ts
interface HistoryFrontier { size: number; peaks: (Hash | null)[] }
emptyHistoryFrontier(): HistoryFrontier
appendHistory(frontier: HistoryFrontier, leaf: Uint8Array): Promise<HistoryFrontier>
historyFrontierRoot(frontier: HistoryFrontier): Promise<Hash>
```

`size` is the count of appended leaves, from zero through `Number.MAX_SAFE_INTEGER`. `peaks[h]` is the hash of the rightmost completed subtree of `2^h` leaves when bit `h` of `size` is set, and `null` otherwise. The array has exactly the highest occupied bit index plus one slots; an empty frontier is `{ size: 0, peaks: [] }`. Each hash is exactly 64 lowercase hexadecimal characters. The object has only enumerable data properties `size` and `peaks`; the dense plain array has no extra properties. Malformed runtime state is rejected before hashing. The public type does not make caller objects immutable, so callers should replace stored frontier values with the returned state rather than mutate them.

Appending hashes the supplied bytes with the existing RFC leaf domain (`SHA256(0x00 || leaf)`). Each occupied low peak is merged as `SHA256(0x01 || existingPeak || carry)`, then cleared. The first empty slot receives the carry. The function copies the input frontier and leaf bytes before its first asynchronous hash and returns a new object and peaks array. It rejects malformed leaves and an append from `Number.MAX_SAFE_INTEGER`; rejection does not modify the caller's frontier.

For an empty frontier, the root is `SHA256(empty bytes)`. Otherwise the root folds occupied peaks from lowest to highest slot. Each larger peak becomes the left child of the accumulated right root. This matches the RFC 9162 largest-power-of-two split for chronological leaves. Bit positions use integer remainder and division rather than JavaScript's 32-bit bitwise operators or floating logarithms near the safe-integer limit. Append and root each perform O(log N) work and retain O(log N) hashes; the cost of copying and hashing the newly supplied leaf bytes is additional.

The frontier alone cannot generate inclusion or consistency proofs. Existing supplied-tree proof functions remain separate. The frontier also does not authenticate a root or make an append durable. A future storage adapter must atomically record the leaf and its new frontier with the product transition, compare the expected prior head to prevent competing writers, and bind a published checkpoint to the resulting size and root. No database transaction, adapter, queue, or application release policy is implemented in this package increment.

## Evidence and limits

`src/hash.ts:20`, `src/hash.ts:25`, and `src/hash.ts:33` define the reused SHA-256, leaf, and node hash domains. `src/history.ts:49` and `src/history.ts:58` define the existing RFC tree root. `test/history-frontier.test.ts` compares every sequential prefix from 0 through 129 leaves with both that root and an independent recursive Node SHA-256 oracle. It also covers malformed size and shape, strict hash encoding, sparse and accessor arrays, extra keys, non-byte leaves, near-safe-integer arithmetic, overflow, input snapshots before the first await, and caller-state preservation. Reversing the carry merge order caused the root comparison to fail; the correct order was restored.

The first red run failed because `emptyHistoryFrontier` was absent. The broader red run had six failures for the missing append export and validation. The wrong-order carry mutation failed the root oracle comparison (`81394c68…` received versus `ecce66a1…` expected). After restoring the merge order, `pnpm test` passed 400 tests across 7 files; `pnpm typecheck`, `pnpm build`, a built package-name ESM import smoke, `git diff --check`, and the scoped engineering smell scan all exited successfully. This standalone package has no lint script. No application, database, or navigation code changed, so application lint, typecheck gate, integration, and Playwright checks do not apply to this increment.

The near-safe-integer tests use synthetic peak hashes to exercise arithmetic and validation; they do not represent an actual history of that size. A selected compiled-module browser smoke passed 24 checks each in Chromium 149.0.7827.55, Firefox 151.0, and WebKit 26.5, including frontier/full-tree root equivalence; the complete unit suite was not run in browsers. Formal correctness, concurrent shared-memory mutation, database durability, authenticated checkpoint publication, and full application integration remain unverified.
