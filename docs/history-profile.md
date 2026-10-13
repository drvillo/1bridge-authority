# History integrity profile

This increment implements an ordered SHA-256 history tree and proofs for supplied trees. It does not implement receipt authentication, storage, observer discovery, authority policy, AKDs, or Bitcoin verification. Independently known receipts are needed to compare divergent histories; a supplied history cannot disclose an unknown hidden history. Releases continue offline under the selected nonblocking policy.

The verifiers check a **supplied root/size/path statement**. Proofs must be checked against an independently trusted **root and size pair**. An opaque sibling hash does not disclose its subtree size: the inclusion path for index 2 in a seven-leaf tree can also reconstruct the same hash when size 8 is claimed. RFC verification cannot reject every incorrectly claimed size from that root hash alone. The unit test `requires a trusted root-size pair because sibling hashes hide subtree sizes` (`test/history.test.ts:132`) records this limitation; malformed bounds and size changes requiring incompatible paths are rejected. Later authenticated checkpoints must bind declared size, and observer replay must check leaf coverage; neither is implemented here.

## Ground truth and engineering plan

- The package is ESM, exporting `dist/index.js` and `dist/index.d.ts` (`package.json:5`, `package.json:17–21`).
- The installed checks are `pnpm test`, `pnpm typecheck`, and `pnpm build` (`package.json:23–26`). No app files are changed; app-specific checks do not apply.
- [RFC 9162 section 2.1](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1) defines the tree shape, domain prefixes, inclusion paths, and consistency `SUBPROOF` recurrence. This profile fixes the algorithm to SHA-256 and lowercase hexadecimal hashes.
- Roots and supplied proof statements are exercised against the independent oracle (`test/oracle.ts:17`, `test/history.test.ts:34`, `test/history.test.ts:86`, `test/history.test.ts:249`). Malformed-runtime rejection and snapshots are exercised by the unit cases below; built ESM exports passed the recorded import smoke.
- Unverified: formal correctness proof, upstream differential compatibility, actual browser execution, production capacity, and complete authority-library readiness.

Engineering workflow:

- [x] 1. Ground truth: standalone caller → pure library; no route, Prisma model, or persisted state applies.
- [x] 2. Plan: file ownership and names recorded below.
- [x] 3. Failing tests at the unit layer observed for each subtask.
- [x] 4. Smallest implementation passing those tests.
- [x] 5. Boy Scout and smell review of touched files; no unrelated cleanup.
- [x] 6. Test, typecheck, build, and built ESM import verification.

## Journey and states

| Caller step | Function | Input → result | Failure state |
| --- | --- | --- | --- |
| Commit an ordered supplied tree | `hashLeaf`, `hashNode`, `merkleRoot` | bytes → hash | Generators reject malformed inputs |
| Prove one supplied entry | `inclusionProof`, `verifyInclusion` | tree/index or leaf/path/root → path or boolean | Verifier returns false for malformed or mismatched evidence |
| Compare two known supplied commitments | `consistencyProof`, `verifyConsistency` | tree/prefix or two sizes/roots/path → path or boolean | Verifier returns false if the prefix cannot be established |

## Changes

- `src/hash.ts`: SHA-256 domains, encoding, and hash validation using browser-native WebCrypto.
- `src/history.ts`: RFC-shaped root, inclusion, and consistency generation/verification; safe integer arithmetic and input snapshots.
- `src/index.ts`: only the requested public named exports.
- `test/oracle.ts`: independent synchronous Node-crypto frontier root oracle, confined to tests.
- `test/history.test.ts`: deterministic boundary, exhaustive small-tree, malformed-input, mutation, and divergent-history cases.
- `docs/history-profile.md`: API contract, algorithm/test mappings, limits, and executed evidence.

## Proposed names

All names below are recorded before production implementation. Public signatures were selected by the coordinator. No name-strain signal was found; the RFC `known` flag in the private consistency recurrence is retained because it represents whether the prefix subtree hash is already known.

| Name | Honest description | Decision |
| --- | --- | --- |
| `Hash` | Lowercase 64-character SHA-256 hexadecimal string | Public alias; runtime validation required |
| `hashLeaf` | Hash leaf bytes under the leaf domain | Requested public API |
| `hashNode` | Hash two decoded child hashes under the node domain | Requested public API |
| `merkleRoot` | Commit the complete ordered supplied tree | Requested public API |
| `inclusionProof` | Generate the supplied leaf's RFC inclusion path | Requested public API |
| `verifyInclusion` | Check supplied inclusion evidence against a root | Requested public API |
| `consistencyProof` | Generate the supplied prefix's RFC consistency path | Requested public API |
| `verifyConsistency` | Check both supplied roots reconstruct from one path | Requested public API |
| `sha256` | Digest owned bytes to SHA-256 | Internal hashing primitive |
| `encodeHash` | Encode digest bytes as lowercase hexadecimal | Private to hash module |
| `decodeHash` | Validate and decode hexadecimal hash bytes | Private to hash module |
| `validHash` | Recognize exact lowercase SHA-256 hexadecimal encoding | Internal predicate |
| `splitSize` | Find the largest power of two below a subtree size | Private shape arithmetic |
| `rootHash` | Hash an owned range of supplied leaves recursively | Private tree primitive |
| `inclusionPath` | Apply the RFC inclusion recurrence to an owned range | Private proof recurrence |
| `consistencyPath` | Apply RFC SUBPROOF to an owned range | Private proof recurrence |
| `validSize` | Recognize a nonnegative safe integer size/index | Private predicate |
| `snapshotLeaves` | Validate a leaf array and copy every leaf before awaiting | Private ownership boundary |
| `snapshotProof` | Validate bounded proof array entries and copy them before awaiting | Private proof ownership boundary; indexed reads avoid custom iterators hiding malformed entries |
| `proofLimit` | Compute an integer tree-height bound without logarithm rounding | Private proof preflight bound |
| `oracleLeaf` | Compute a leaf hash with test-only Node crypto | Test oracle |
| `oracleNode` | Compute a node hash with test-only Node crypto | Test oracle |
| `oracleRoot` | Fold test leaf hashes through an iterative frontier | Test oracle independent from production recursion |
| `fixtureLeaves` | Build deterministic binary and UTF-8 fixtures | Test fixture |

## Test plan

| Behaviour | Layer | Assertion | Reason |
| --- | --- | --- | --- |
| SHA domains, empty tree, split boundaries | Unit | Exact hashes and equality with iterative oracle | Pure bytes → hash contract |
| Inclusion for every index | Unit | Generated path verifies against independent root | Pure supplied-tree proof contract |
| Consistency for every small prefix and boundary sizes | Unit | One path reconstructs both independent roots | Pure supplied-history contract |
| Invalid bounds/encodings/paths | Unit | Generators reject; verifiers return false | Public runtime boundary |
| Caller mutation after invocation | Unit | Original snapshot result remains valid | Async ownership boundary |
| Forked histories | Unit | Own inclusions pass; incompatible roots fail consistency | Limits of known evidence |

## Principles and scope

SRP: hashing owns domains/encoding; history owns tree shape/proofs. DRY: shared root recurrence and validation predicates. YAGNI: no persistence, signatures, receipts, or policy framework. KISS: zero runtime dependencies, existing source/test directories, straightforward RFC recurrences and numeric division/remainders. No cleanup outside owned files; no prior implementation exists to refactor. Verification will use the package's actual scripts and a built ESM import smoke test.

## Executed evidence

Executed on 2026-10-13 with Node v26.5.0, pnpm 10.29.3, TypeScript 5.9.3, and Vitest 3.2.7. All commands below ran from the standalone package root.

| Subtask | Red command/result | Green result |
| --- | --- | --- |
| Hash/root | `pnpm test -- test/history.test.ts`: 47 failed; missing `hashLeaf`, `hashNode`, `merkleRoot` exports/features; first assertion expected the module to contain `hashLeaf` | Same command: 47 passed |
| Inclusion | `pnpm exec vitest run test/history.test.ts -t 'inclusion proofs'`: 51 failed, 47 skipped; missing inclusion exports/features | Full file: 99 passed after the size-statement spec finding below |
| Consistency | `pnpm exec vitest run test/history.test.ts -t 'consistency proofs'`: 56 failed, 99 skipped; missing consistency exports/features | Full file: 155 passed |
| Indexed array snapshots | `pnpm exec vitest run test/history.test.ts -t 'custom iterator'`: 3 failed, 155 skipped; malformed leaf array resolved rather than rejecting and both malformed proof arrays returned true | Targeted command: 3 passed, 155 skipped; full suite: 158 passed |

The initial inclusion test expected changing size 7 to 8 at index 2 to fail. The exact RFC algorithm returned true (`expected true to be false`, initial `pnpm test -- test/history.test.ts`: 97 passed, 1 failed). Inspection of RFC 9162 section 2.1.3.2 confirmed the opaque-subtree limitation. The test now rejects incompatible size 9 (`test/history.test.ts:123`) and records size 8 acceptance explicitly (`test/history.test.ts:132`). This was a corrected test/spec expectation, not an algorithm change. Additional trailing LF/CR/CRLF encoding negatives passed against the existing strict encoding predicate; no production change was needed.

Required invariant mutations were applied separately, tested, and restored:

| Temporary mutation | Exact targeted command | Observed failure | After restoration |
| --- | --- | --- | --- |
| Leaf prefix `0x00` → `0x02` | `pnpm exec vitest run test/history.test.ts -t 'uses the leaf domain' --reporter dot` | 1 failed, 157 skipped; empty leaf expected `6e340b9c…`, received `dbc1b4c9…` | Same command: 1 passed, 157 skipped |
| Node prefix `0x01` → `0x02` | `pnpm exec vitest run test/history.test.ts -t 'uses the node domain' --reporter dot` | 1 failed, 157 skipped; expected `6bcf0e2e…`, received `0df61daf…` | Same command: 1 passed, 157 skipped |
| Omit `oldHash === oldRoot` | `pnpm exec vitest run test/history.test.ts -t 'rejects a mismatched old root' --reporter dot` | 1 failed, 157 skipped; `expected true to be false` | Same command: 1 passed, 157 skipped |

Final gates after restoration:

| Gate | Recorded result |
| --- | --- |
| `pnpm test` | Exit 0; 1 file, 158 tests passed; 3.66 s test execution / 4.01 s total |
| `pnpm typecheck` | Exit 0; `tsc --noEmit` |
| `pnpm build` | Exit 0; `tsc -p tsconfig.build.json` |
| Built ESM self-reference import | Exit 0; package-name import resolved `dist/index.js`; exactly seven runtime named exports; empty root, both hash functions, inclusion generation/verification, consistency generation/verification exercised |
| `bash /Users/fvivoli/opt/projects/ubo-guard/.cursor/skills/engineering-standards/scripts/smell-scan.sh --files src/hash.ts src/history.ts src/index.ts test/oracle.ts test/history.test.ts` | Exit 0; five files scanned, no structural or name findings |

The built ESM import gate was executed with this exact command:

```sh
node --input-type=module <<'NODE'
import assert from 'node:assert/strict'
import * as history from '@drvillo/1bridge-authority'
assert.deepEqual(Object.keys(history).sort(), ['consistencyProof', 'hashLeaf', 'hashNode', 'inclusionProof', 'merkleRoot', 'verifyConsistency', 'verifyInclusion'])
const empty = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
assert.equal(await history.merkleRoot([]), empty)
const leaves = ['C0', 'y', 'z'].map(value => new TextEncoder().encode(value))
const root = await history.merkleRoot(leaves)
const leafHash = await history.hashLeaf(leaves[0])
assert.match(await history.hashNode(leafHash, leafHash), /^[0-9a-f]{64}$/)
assert.equal(await history.verifyInclusion(leaves[2], 2, 3, await history.inclusionProof(leaves, 2), root), true)
const oldRoot = await history.merkleRoot(leaves.slice(0, 2))
assert.equal(await history.verifyConsistency(2, 3, oldRoot, root, await history.consistencyProof(leaves, 2)), true)
console.log('Built ESM self-reference import: seven runtime exports, empty root, hash, inclusion, consistency passed')
NODE
```

No app gates, database integration tests, or navigation E2E tests were run because no app, persistence, or navigation behavior changed. This package has no lint script; none was invented. Self-review confirmed the root export surface (`src/index.ts:1`), no Node imports in production (`src/hash.ts:21` uses global WebCrypto), numeric division/remainders rather than 32-bit bitwise operations (`src/history.ts:98`, `src/history.ts:155`), bounded proof preflight (`src/history.ts:36`), and comparison of both consistency roots (`src/history.ts:176`). The deliberately retained private recurrence flag and public positional arguments follow the selected RFC/API contract; there is no unrelated cleanup commit.

## Public contract and implementation/test mapping

```ts
type Hash = string // exactly 64 lowercase hexadecimal characters at runtime
hashLeaf(leaf: Uint8Array): Promise<Hash>
hashNode(left: Hash, right: Hash): Promise<Hash>
merkleRoot(leaves: readonly Uint8Array[]): Promise<Hash>
inclusionProof(leaves: readonly Uint8Array[], index: number): Promise<Hash[]>
verifyInclusion(leaf: Uint8Array, index: number, size: number,
  proof: readonly Hash[], root: Hash): Promise<boolean>
consistencyProof(leaves: readonly Uint8Array[], oldSize: number): Promise<Hash[]>
verifyConsistency(oldSize: number, newSize: number, oldRoot: Hash,
  newRoot: Hash, proof: readonly Hash[]): Promise<boolean>
```

`Hash` is an alias rather than a branded or nominal type. Public generators validate runtime inputs and reject their promises for malformed input or bounds. Verifiers return false for malformed input, failed reconstruction, or hashing/runtime failure. They do not authenticate roots, checkpoints, identities, timestamps, or leaves. Supported byte inputs are Uint8Array instances (including Node Buffers in the Node test/runtime environment); other typed-array element types are rejected.

| Profile rule / function | Implementation | Tests |
| --- | --- | --- |
| Exact lowercase hash encoding | `src/hash.ts:3`, `src/hash.ts:11` | `test/history.test.ts:39`, `test/history.test.ts:154`, `test/history.test.ts:346` |
| SHA-256 WebCrypto / leaf `0x00` / node `0x01` with decoded children | `src/hash.ts:20`, `src/hash.ts:25`, `src/hash.ts:33` | `test/history.test.ts:20`, `test/history.test.ts:27`; two prefix mutation failures above |
| Empty root and largest-power-of-two recursive split | `src/history.ts:17`, `src/history.ts:49`, `src/history.ts:58` | Literal empty digest at `test/history.test.ts:16`; frontier oracle at `test/oracle.ts:17`; 39 tree sizes at `test/history.test.ts:34` |
| Inclusion PATH recurrence and fn/sn verifier | `src/history.ts:63`, `src/history.ts:78`, `src/history.ts:84` | 1,137 index statements at `test/history.test.ts:86`; exact seven-leaf node order at `test/history.test.ts:95`; singleton at `test/history.test.ts:108` |
| Consistency SUBPROOF recurrence and both-root verifier | `src/history.ts:116`, `src/history.ts:131`, `src/history.ts:138` | 1,177 prefix statements at `test/history.test.ts:249` (all old/new pairs 0–33, plus every prefix at 63/64/65/127/128/129); exact seven-leaf node order at `test/history.test.ts:260` |
| Empty prefix requires SHA-256 empty old root / empty proof | `src/history.ts:146` | `test/history.test.ts:276` |
| Equal sizes require equal roots / empty proof | `src/history.ts:150` | `test/history.test.ts:285` |
| Both roots and all proof nodes are required | `src/history.ts:97`, `src/history.ts:162`, `src/history.ts:176` | `test/history.test.ts:138`, `test/history.test.ts:292`, `test/history.test.ts:299`, `test/history.test.ts:328`; omitted old-root comparison mutation above |
| Safe nonnegative integers and bounds | `src/history.ts:3`, `src/history.ts:80`, `src/history.ts:88`, `src/history.ts:133`, `src/history.ts:142` | `test/history.test.ts:170`, `test/history.test.ts:361`; synthetic >32-bit/MAX_SAFE_INTEGER statements at `test/history.test.ts:205`, `test/history.test.ts:387` |
| Proof lengths bounded before hashing | `src/history.ts:7`, `src/history.ts:36` | 100,000-node arrays rejected without digest calls at `test/history.test.ts:187`, `test/history.test.ts:377` |
| Owned arrays/bytes before first await | `src/hash.ts:27`, `src/history.ts:23`, `src/history.ts:36`, `src/history.ts:92` | `test/history.test.ts:55`, `test/history.test.ts:69`, `test/history.test.ts:221`, `test/history.test.ts:231`, `test/history.test.ts:395`, `test/history.test.ts:405` |
| Malformed entries cannot hide behind custom iterators | `src/history.ts:28`, `src/history.ts:41` | `test/history.test.ts:63`, `test/history.test.ts:197`, `test/history.test.ts:414` |
| Known histories can conflict while own inclusions pass | `src/history.ts:176` | `test/history.test.ts:422`: C0→x vs C0→y→z; comparisons from C0 and the y-prefix remain valid, so y/z alone cannot disclose unknown x |

## Resource limits and remaining work

Roots and generators snapshot all supplied leaves and arrays before awaiting, using memory proportional to total leaf bytes plus leaf count. They traverse the supplied tree rather than retaining a persistent tree/cache. Computing a root or one generated proof hashes up to a linear number of supplied leaves; generating proofs for every index independently repeats work. Recursion depth is logarithmic in leaf count. No maximum generator leaf count or leaf-byte budget is imposed; callers must bound them for their workload.

Inclusion verification accepts at most the integer tree height (53 proof nodes at the maximum safe integer size). Consistency accepts at most height plus one (54). Every supplied node is validated before hashing; success requires the full path to terminate. Inclusion still copies/hashes the supplied leaf bytes, with no leaf-byte cap. Consistency verification's work is bounded by proof length; an empty-prefix check hashes the empty input. Safe integer bounds do not claim that allocating or generating a tree near Number.MAX_SAFE_INTEGER is practical; large-size tests exercise verifier arithmetic with synthetic subtree commitments only.

The suite covers 48 hash/root cases, 53 inclusion cases, and 57 consistency cases. Test duration is execution evidence, not a performance benchmark. No formal proof, third-party/upstream differential test, real browser execution, threaded SharedArrayBuffer snapshot guarantee, authenticated receipt/checkpoint implementation, observer discovery/storage, authority authorization, or complete authority-library readiness is claimed. The nonblocking standard and strict release policy is an application decision; these functions neither block releases nor implement that policy.
