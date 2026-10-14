# Append-only history frontier implementation plan

> **For agentic workers:** Use Superpowers subagent-driven development and test-driven development. Work in focused commits with specification and quality review after implementation.

**Goal:** Update an RFC 9162 history root for one appended leaf without hashing every prior leaf.

**Architecture:** Retain the completed power-of-two subtrees of the current chronological prefix as an immutable frontier. A carry merges peaks on append. The root folds retained peaks in RFC 9162 tree order. The database adapter later stores frontier and leaf in one product transaction; this portable module owns only calculations and validation.

**Tech stack:** Existing TypeScript 5.9/WebCrypto SHA-256/Vitest package; no dependency.

## Ground truth

- `src/history.ts:48` recomputes a root from all leaf bytes and has exact RFC 9162 inclusion/consistency functions. It does not retain append state.
- `src/hash.ts:20` implements native SHA-256; `hashLeaf` uses `0x00` and `hashNode` uses `0x01`. Reuse them unchanged.
- `test/history.test.ts` tests independent iterative roots and proof boundaries. New frontier tests compare against those roots, not a second copy of frontier code.

## Journey and states

| Step | Caller | State before → after | Failure |
|---|---|---|---|
| Initialize | Publisher/fixture | No entries → `{size:0,peaks:[]}` | None |
| Append | Publisher supplies exact canonical log leaf bytes | Valid frontier of N leaves → valid frontier of N+1 leaves | Invalid frontier/leaf or overflow rejects without mutation |
| Publish root | Publisher/checkpoint builder | Valid frontier → RFC 9162 root | Invalid peak shape/hash rejects |
| Persist | Later app adapter | Journal leaf and frontier atomically stored | Out of scope for pure module; requires real Postgres test |

## Changes

- `src/history-frontier.ts`: immutable `HistoryFrontier`, `emptyHistoryFrontier`, `appendHistory`, `historyFrontierRoot`.
- `src/index.ts`: public frontier exports and type.
- `test/history-frontier.test.ts`: root equivalence, oracle, validation, mutation and overflow.
- `docs/history-frontier-profile.md`: exact peak ordering, complexity and persistence boundary.

## Exact contract

`HistoryFrontier` is `{size:number,peaks:(Hash|null)[]}`. `size` is a nonnegative safe integer. `peaks[h]` is the root of the rightmost completed 2^h subtree represented by bit h of size. A set bit requires a lowercase 64-hex hash; an unset bit requires null. For size zero peaks is empty. For nonzero size, peaks length is the highest occupied bit index plus one; calculate that length by repeated integer division to avoid `Math.log2` rounding near 2^53. Generate and verify with arithmetic `% 2` and `Math.floor(size/2)`, never JavaScript bitwise operators that truncate above 32 bits. Reject max-safe-size append overflow. Snapshot input arrays/bytes before the first await.

`emptyHistoryFrontier()` returns `{size:0,peaks:[]}`. `appendHistory(frontier,leafBytes)` hashes leaf with existing 0x00 domain; carry over every occupied low peak with `hashNode(existingPeak,carry)`, clear those peaks, set the first empty peak, increment size, and return a new frontier. `historyFrontierRoot(frontier)` returns `SHA256(empty bytes)` at size zero; otherwise fold occupied peaks from smallest h to largest h with `hashNode(largerPeak, accumulatedRightRoot)`. This is the RFC 9162 largest-power-of-two split shape; append and root cost O(log N), storage O(log N). This does not supply inclusion/consistency proofs or durability; existing history functions or cached nodes/records provide them.

## Proposed names

| Name | Responsibility | Name strain / decision |
|---|---|---|
| `emptyHistoryFrontier` | Construct the empty valid state | Single purpose; keep |
| `appendHistory` | Calculate one append | One operation; keep |
| `historyFrontierRoot` | Calculate one root from a frontier | Single purpose; keep |
| `HistoryFrontier` | Exact immutable peak state | Single role; keep |

## Test-first steps

1. Add failing tests importing the new exports and asserting empty frontier and empty root. Run `pnpm exec vitest run test/history-frontier.test.ts`; observe missing export failure. Implement empty state/root minimally.
2. Add failing tests appending literal bytes 1, 2, 3, 4, 7, 8, 9 and comparing roots to existing `merkleRoot` plus an independent Node SHA-256 frontier-independent oracle. Implement carry and peak fold. Include 0…129 sequential prefixes and adversarial unbalanced sizes.
3. Add failing tests for exact canonical state: malformed size/hash/peak count/occupancy, sparse arrays/getters/extra fields, malformed leaf and max-safe overflow; verify failed append leaves caller object unchanged. Implement snapshot validation with strict plain data shapes.
4. Add failing async mutation tests changing caller leaf/peaks after invocation; returned root must reflect the pre-await state. Deliberately reverse carry merge order and observe a test failure, then restore.
5. Document byte/order profile and tested limits. Run full `pnpm test`, `pnpm typecheck`, `pnpm build`, compiled ESM smoke, `git diff --check`, scoped smell scan. Commit only this increment. Request specification then quality review.

## Principles, smells and verification

Reuse existing RFC hash domains, avoid a second history algorithm, and keep storage/queue concerns outside the pure module. A tree-frontier interface is warranted by append costs; no generalized data-structure framework. The adapter will later atomically persist frontier with product transition and log leaf under a DB head compare-and-swap. The app's lint/typecheck:gate/integration gates apply only when its source changes.

## Execution and review record

- Implemented as focused commit `2f5a49a` after the missing-export red run, six broader red cases, and a deliberately reversed carry-merge mutation that failed the independent root oracle. The implementation and profile record exact runtime limits.
- Fresh specification review passed. Fresh quality review accepted the increment without findings; the reviewer also checked synthetic high-bit frontier sizes independently.
- Parent verification after the implementation: `pnpm test` passed 400 tests across 7 files, `pnpm typecheck`, `pnpm build`, and `git diff --check` passed. A built ESM import smoke matched a five-leaf full-tree root. A selected compiled-module browser smoke passed 24 checks each in Chromium 149.0.7827.55, Firefox 151.0, and WebKit 26.5, including a frontier-versus-full-tree root comparison. This is not the full suite in browsers.
- No app source, database, or navigation contract changed in this increment, so app lint/typecheck:gate/integration/E2E gates do not apply. Persistence, authenticated checkpoints, and observer reconciliation remain separate work.
