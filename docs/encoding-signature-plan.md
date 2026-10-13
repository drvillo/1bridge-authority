# Canonical encoding and signature increment plan

> For agentic workers: use Superpowers subagent-driven-development, test-driven-development and independent spec/quality review.

Goal: establish one unambiguous signed-byte contract and native P-256 signature codec for attributable approvals/root/receipt layers. This is separate from storage/receipt transport, so it does not depend on archival transport.

Architecture: canonical restricted JSON, domain-separated message bytes and native WebCrypto ECDSA P-256/SHA-256. Browser/Node core, no runtime dependencies. Application policy/key custody remains a subsequent consumer rather than guessed semantics inside signing.

## Ground truth

The public library history foundation owns SHA-256 and chronological proofs, not signatures. The existing app retains X25519/mk1 envelopes; it does not acquire signing authority by converting an encryption key. Shared design calls for new native P-256 roles. This increment introduces no app changes.

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
