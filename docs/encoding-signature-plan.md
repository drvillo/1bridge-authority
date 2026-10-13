# Canonical encoding and signature increment plan

> For agentic workers: use Superpowers subagent-driven-development, test-driven-development and independent spec/quality review.

Goal: establish one unambiguous signed-byte contract and native P-256 signature codec for attributable approvals/root/receipt layers. This is separate from storage/receipt transport, so it does not depend on archival transport.

Architecture: canonical restricted JSON, domain-separated message bytes and native WebCrypto ECDSA P-256/SHA-256. Browser/Node core, no runtime dependencies. Application policy/key custody remains a subsequent consumer rather than guessed semantics inside signing.

## Ground truth

The public library history foundation owns SHA-256 and chronological proofs, not signatures. The existing app retains X25519/mk1 envelopes; it does not acquire signing authority by converting an encryption key. Shared design calls for new native P-256 roles. This increment introduces no app changes.

Verified library evidence: `src/index.ts:1–2` exposes only hashes/history; `src/hash.ts:20–23` supplies internal native SHA-256. `package.json:23–26` defines test/typecheck/build; `tsconfig.json:6–9` includes DOM WebCrypto types. No route, model or DB state applies to pure library calls. App encryption behavior is a coordinator-supplied scope constraint, not reverified in this increment.

Engineering workflow:

- [x] 1. Ground truth: caller → pure library; no route, Prisma or persisted states.
- [x] 2. Plan: file ownership and proposed names recorded before code.
- [x] 3. Failing unit tests observed for each increment.
- [x] 4. Smallest implementation passing those tests.
- [x] 5. Scoped Boy Scout pass and advisory smell review.
- [x] 6. Test, typecheck, build and built ESM verification.

## Journey and states

| Caller | Transition | Failure |
|---|---|---|
| Record producer | Allowed JSON → canonical bytes | Ambiguous/unsupported values reject before signing. |
| Key owner | Generate/import dedicated signing key → purpose-specific signature | Wrong algorithm/type/curve or malformed key rejects. |
| Independent verifier | Expected purpose/record/public key → true/false | Wrong purpose/body/key, malformed signature or unsupported bytes reject. |

No DB or routes are involved. Approval attribution comes from later authenticated key binding; this layer verifies a signature under a supplied key only.

## Files and proposed names

- src/canonical.ts: JsonValue type, canonicalJson, canonicalBytes, parseCanonical; private assertString, encodeValue, parseValue. Max record bytes 1MiB and nesting32; safe integers only, no negative zero/fractions/NaN/infinity; no undefined, holes, cycles, symbols, getters or custom prototypes. Strings reject lone surrogates. Objects sort UTF-16 keys, using JSON.stringify for string escaping. Serialized parsing requires exact canonical re-encoding equality, rejecting duplicate keys/alternate escapes/order.
- src/signatures.ts: generateSigningKey, exportSigningPublicKey, importSigningPublicKey, exportSigningPrivateKey, importSigningPrivateKey, signingKeyId, signRecord, verifyRecord. Native ECDSA P-256/SHA-256, fixed64byte P1363 signatures and canonical base64url SPKI/PKCS8. Private bytes are secret exports requiring downstream custody; no plaintext persistence is introduced.
- src/encoding.ts: encodeBase64Url, decodeBase64Url; strict canonical alphabet/length/unusedbits and explicit decoded-size limits. Use browser-native btoa/atob, no Buffer/Node imports.
- test/canonical.test.ts, test/signatures.test.ts, test/encoding.test.ts: independent expected bytes and native cross-verification/adversarial cases.
- src/index.ts: named exports.

If private helpers beyond these names are needed, record them before code. No conditional/conjunction names needed.

Additional private names recorded before implementation:

| Name | Honest description | Name-strain signals / decision |
|---|---|---|
| `EncodingState` | Canonical output chunks and consumed UTF-8 budget | Internal shape; one output state |
| `appendEncoded` | Append one encoded fragment within the byte budget | None; private canonical byte accounting |
| `encodeArray` | Encode dense own array entries | None; isolate array shape validation |
| `encodeObject` | Encode sorted own object data properties | None; isolate object shape validation |
| `assertSigningKey` | Require native P-256 key of expected type and usage | None; one key profile guard |
| `recordBytes` | Produce the purpose-domain canonical record snapshot | None; one message-byte contract |
| `keyBytes` | Decode a bounded nonempty key encoding | None; one key transport bound |
| `concatBytes` | Concatenate two byte arrays into owned bytes | None; private byte ownership |

Test fixture names: `nestedArray` constructs a bounded-depth fixture; `nativePair` creates an ephemeral native key fixture; `nativePublic` and `nativePrivate` export ephemeral native fixture bytes; `nativeMessage` supplies independently literal signed bytes. Test helpers are confined to unit suites and never log secret key material.

Container nesting is counted from the root container as one, with a maximum of 32 containers. Objects encode every own string data property (including nonenumerable data); accessors and symbol properties reject. Arrays require the ordinary Array prototype, dense own indexed data properties, and no additional own keys. Descriptor reads avoid invoking getters, iterators or `toJSON`.

## Test plan

| Behavior | Layer | Outcome assertion | Why |
|---|---|---|---|
| Canonical records and serialized rejection | Unit | Literal bytes; unsupported/ambiguous inputs throw | Pure synchronous functions |
| Canonical base64url and bounds | Unit | Literal vectors; invalid encodings throw before decode | Pure codec |
| Signing and independent native verification | Unit with real WebCrypto | Native verifier accepts exact bytes; altered inputs return false | No storage or browser flow involved |

No new dependencies or directory conventions are introduced. The profile lives in the existing `docs/encoding-signature-profile.md` convention. Cleanup is limited to owned files; history behavior and tests remain untouched.

## Fixed API and byte contract

```ts
export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue }
export function canonicalJson(value: unknown): string
export function canonicalBytes(value: unknown): Uint8Array
export function parseCanonical(serialized: string | Uint8Array): JsonValue
export function encodeBase64Url(bytes: Uint8Array): string
export function decodeBase64Url(encoded: string, maxBytes?: number): Uint8Array
export function generateSigningKey(): Promise<CryptoKeyPair>
export function exportSigningPublicKey(key: CryptoKey): Promise<string>
export function importSigningPublicKey(encoded: string): Promise<CryptoKey>
export function exportSigningPrivateKey(key: CryptoKey): Promise<string>
export function importSigningPrivateKey(encoded: string): Promise<CryptoKey>
export function signingKeyId(publicKey: CryptoKey): Promise<string>
export function signRecord(purpose: string, record: unknown, privateKey: CryptoKey): Promise<string>
export function verifyRecord(purpose: string, record: unknown, signature: string, publicKey: CryptoKey): Promise<boolean>
```

Codec permits empty bytes; decoded-size default is 1 MiB, explicitly supplied limit must be a nonnegative safe integer. Key import accepts at most 1024 decoded bytes; signatures exactly 64 decoded bytes. Exported/imported public SPKI uses native re-export canonical equality; private PKCS8 is secret material. Native generate/import is extractable to support explicit encrypted-custody/kit consumers.

Signed message bytes are TextEncoder.encode('1bridge.authority/v1\n' + purpose + '\n') with actual LF characters, concatenated with canonicalBytes(record). Purpose is ASCII regex `^[a-z][a-z0-9._-]{0,63}$`. Public signing key ID is SHA256(TextEncoder.encode('1bridge.authority/v1/public-key\n') with actual LF, concatenated with decoded canonical SPKI). Key ID fingerprint alone is not authenticated identity. Wrong algorithms, curves, types/usages, record or signature yield rejection; signing/key import/export throws expected invalid input, verifyRecord returns false.

## Test-first tasks

1. Write canonical tests and observe failing imports/feature assertions before production code. Exact expected fixture: `{b:2,a:'x'}` → `{"a":"x","b":2}`; UTF8/canonical strings/arrays/null; reject every unsupported value above. Parse rejects duplicate keys, key order changes, padded whitespace, alternate escapes, invalid UTF8 or byte-order mark, wrong depth/size and serialized negative-zero/fractional/unsafe values. No getter executes while validating unsupported objects. Native JSON escaping is not a formal full RFC8785 claim; this is an explicitly restricted profile.
2. Implement canonical recursion with depth/size limits and descriptors/plain-value validation; test holes and custom iterators cannot bypass entry validation. Deliberately skip key sorting or duplicate-key canonical equality; observe failure, restore.
3. Write base64url tests before implementation: literal known vectors, roundtrip binary, empty when codec permits, bad alphabet/padding/length/nonzero trailing bits/type and max size. Decode canonical equality enforces one encoding; no ignored trailing data. Run red, implement, run green.
4. Write signing tests before implementation: generated/export/import P256 roundtrips; exact64-byte signature; verify against independent native WebCrypto bytes computed from explicit domain/purpose fixture; native-produced signature verifies here; altered record/purpose/key rejects; malformed signature/runtime inputs return false; wrong P384/HMAC/type/imported-key usages reject. Private export/import tests use ephemeral fixture keys and no logging of secret bytes.
5. Define signed message bytes exactly: UTF8('1bridge.authority/v1\n' + purpose + '\n') followed by canonicalBytes(record), purpose regex [a-z][a-z0-9._-]{0,63}. signer validates expected privateKey algorithm/type/usages; verifier validates supplied public key and exact signature length, catches malformed inputs to false. signingKeyId hashes domain label plus canonical exported public SPKI. Native generation is extractable for explicit encrypted-custody/export consumers; document this rather than claiming secret bytes cannot be exported.
6. Test caller mutation of record and signature input before first await cannot alter a pending calculation. Add limits before accepting untrusted key/signature strings. Mutate purpose binding, watch cross-purpose failure tests, restore.

## Principles, Boy Scout and verification

SRP: canonical records, binary codec and signature operation. DRY: one domain/record encoding, one key profile. KISS: native cryptography and existing dev tools; no JWT/new dependency. No app cleanup or business-policy invention. JSON limits guard untrusted records without a second serialization framework.

Require independent spec review, then quality review. Run full pnpm test/typecheck/build and built-ESM import smoke. Full browser runtime, authority-policy/map/receipt/token/storage and observer gates remain later readiness obligations. Do not claim authenticated customer identity, constant-time JavaScript private operations, independent audit or formal composition correctness from these tests.

Executed implementation evidence (2026-10-13): canonical suite initially failed 11 missing-feature assertions, codec suite 12, signature suite 33. Focused suites then passed 51/38/33; one additional native compressed-SPKI characterization raised the final signature count to 34. Mutations caught omitted sorting (2 failures), omitted canonical parse equality (10), omitted purpose binding (1), and omitted native SPKI re-export equality (1); all restored. Final `pnpm test` passed 281 tests, preserving all 158 history tests; `pnpm typecheck`, `pnpm build`, exact 20-export built-ESM smoke and `git diff --check` passed. Seven-file advisory smell scan reported no findings. This package has no lint, `typecheck:gate`, integration or E2E scripts; real crypto roundtrips are exercised by unit tests against native WebCrypto and Node crypto. Independent reviews are coordinator-owned and not claimed here.

## Codec review fix plan

Ground truth at reviewed baseline `fcdbfa8`: `encodeBase64Url` reads the caller's shadowable `length` property in its byte loop (`src/encoding.ts:6` at that commit). A one-byte Uint8Array with own length 0 encodes empty instead of literal `AQ`; own length 2 appends a nonexistent zero byte. Three first-written unit regressions reproduce these two values and a length accessor without new production code. Native `new Uint8Array(bytes)` copies the internal typed-array byte range without reading the shadowed length or custom iterator; the existing SHA-256 core already copies with this constructor (`src/hash.ts:21`).

Changes: `src/encoding.ts` will encode an owned native snapshot; `test/encoding.test.ts` pins exact actual bytes and no length getter invocation; this plan and profile record evidence. No new function names, dependencies, conventions or unrelated cleanup. Proposed local name `snapshot`: the owned native byte copy, with no name strain.

Journey: caller Uint8Array → native snapshot → exact canonical base64url; malformed non-byte inputs still throw. No routes, model or DB states apply. SRP/DRY/YAGNI/KISS remain the current codec boundary. Verify the focused red/green, temporarily remove the snapshot for the relevant mutation, restore it, then run all tests/typecheck/build, ESM codec smoke, diff check and advisory smell scan.

Executed fix: all three regressions failed for the exact byte mismatch before implementation; native snapshot passed 41 codec tests. Snapshot-removal mutation reproduced three failures and was restored. Final `pnpm test` passed 284/284, preserving all 158 history tests. Typecheck, build, ESM actual-byte/no-getter smoke, diff check and two-file advisory smell scan passed. The fix introduces no new function or cleanup beyond this codec behavior; the API and signing contract remain the same.
