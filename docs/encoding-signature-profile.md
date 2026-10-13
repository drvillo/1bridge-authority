# Canonical encoding and native signing profile

This increment provides bounded canonical record bytes, canonical base64url transport, and signatures under supplied native P-256 keys. A valid signature establishes the supplied key signed the supplied purpose and record. Identity, customer authority, approver roles, policy, receipts, storage, observer operation and encrypted key custody remain consumer responsibilities. The existing app and history implementation are unchanged.

The engineering plan and names were recorded before production implementation in `docs/encoding-signature-plan.md:24`. Pure library calls have no route, Prisma model, or persisted state. The package checks are test, typecheck and build (`package.json:23`); native SHA-256 is internal (`src/hash.ts:20`). Public exports are explicit (`src/index.ts:1`).

## Canonical record contract

`JsonValue`, `canonicalJson`, `canonicalBytes` and `parseCanonical` implement a restricted JSON profile (`src/canonical.ts:1`, `src/canonical.ts:90`, `src/canonical.ts:108`).

- Values are null, booleans, strings without lone UTF-16 surrogates, safe integers excluding negative zero, arrays, or ordinary/null-prototype objects. Fractions, unsafe integers, NaN, infinity, undefined, BigInt, functions and symbols reject (`src/canonical.ts:13`, `src/canonical.ts:66`).
- Object keys sort by UTF-16 code units. Every own string data property is encoded, including nonenumerable data. Accessors, symbols, custom prototypes and cycles reject. Repeated noncyclic references are allowed (`src/canonical.ts:47`, `src/canonical.ts:83`).
- Arrays require Array.prototype, dense own indexed data entries, and no extra own properties. Descriptors avoid property getter, iterator and custom `toJSON` execution (`src/canonical.ts:33`).
- `JSON.stringify` is used only for string escaping; integer and structural bytes are explicit. Canonical serialization is limited to 1 MiB of UTF-8 and 32 nested containers, counting a root container as one (`src/canonical.ts:27`, `src/canonical.ts:82`). Unicode is preserved without normalization. This restricted numeric profile is not a claim of full RFC 8785 conformance.
- Parsing requires exact canonical re-encoding equality. Bytes require fatal UTF-8 decoding, preserve a BOM for rejection, and match the canonical UTF-8 bytes exactly. Duplicate keys, reordered keys, whitespace, alternate escapes and noncanonical number forms reject (`src/canonical.ts:100`, `src/canonical.ts:108`).

The literal fixture `{ b: 2, a: 'x' }` becomes `{"a":"x","b":2}`.

## Binary transport and keys

`encodeBase64Url` accepts Uint8Array, including empty bytes. `decodeBase64Url` requires unpadded URL alphabet, valid length and zero unused trailing bits by exact roundtrip equality (`src/encoding.ts:3`, `src/encoding.ts:10`). Decoding defaults to 1 MiB. An explicitly supplied maximum must be a nonnegative safe integer; explicit undefined rejects. Input length is bounded before alphabet work, native decode and result allocation. Production uses btoa/atob without Buffer or Node imports.

Native keys use ECDSA/P-256; signatures use SHA-256 (`src/signatures.ts:7`). `generateSigningKey` produces extractable public/private keys with verify/sign usage respectively. Imports are extractable. Exporting PKCS8 reveals secret material that the consumer must protect; the library adds no persistence (`src/signatures.ts:38`, `src/signatures.ts:57`). Signing also permits native nonextractable private keys, while their export rejects.

Public export/import uses canonical base64url SPKI; private export/import uses canonical base64url PKCS8. Key imports are nonempty and at most 1024 decoded bytes. Native type, algorithm, curve and exact expected usage are validated. Public imports additionally require exact native SPKI re-export equality, so alternate compressed points and ignored trailing bytes cannot acquire a second encoding for the same public key (`src/signatures.ts:12`, `src/signatures.ts:32`, `src/signatures.ts:49`). Private PKCS8 is validated by native import; public-key identity is derived only from canonical SPKI.

## Exact signed bytes

`signRecord(purpose, record, privateKey)` signs:

```text
UTF8("1bridge.authority/v1" + LF + purpose + LF) || canonicalBytes(record)
```

LF is byte 0x0a. Purpose matches `^[a-z][a-z0-9._-]{0,63}$` over the entire string, including rejecting terminal newline characters. Record bytes are owned before the first await (`src/signatures.ts:27`, `src/signatures.ts:76`).

Signatures are 64-byte IEEE-P1363 r||s encoded as canonical base64url, rather than ASN.1 DER (`src/signatures.ts:79`). This profile does not add low-s normalization or deterministic-signature requirements. `verifyRecord` snapshots the record before awaiting and returns false for malformed runtime inputs, wrong key profile, purpose, body, signature or failed native verification. Producers, imports and exports throw/reject invalid input (`src/signatures.ts:84`).

`signingKeyId(publicKey)` returns lowercase hexadecimal SHA256 over:

```text
UTF8("1bridge.authority/v1/public-key" + LF) || decodedCanonicalSPKI
```

The domain and decoded SPKI are explicit (`src/signatures.ts:71`); this fingerprint alone does not authenticate an identity.

## Implementation and test mapping

| Contract | Production evidence | Unit evidence |
|---|---|---|
| Literal serialization, UTF-16 key order, string escaping | `src/canonical.ts:47` | `test/canonical.test.ts:17`, `test/canonical.test.ts:22`, `test/canonical.test.ts:26` |
| Unsupported values, shapes, no getters/iterators, cycles | `src/canonical.ts:33`, `src/canonical.ts:66` | `test/canonical.test.ts:37`, `test/canonical.test.ts:57`, `test/canonical.test.ts:71`, `test/canonical.test.ts:87` |
| 32-container and exact UTF-8 size bounds | `src/canonical.ts:27`, `src/canonical.ts:82` | `test/canonical.test.ts:97`, `test/canonical.test.ts:102`, `test/canonical.test.ts:134` |
| Canonical parsing, malformed UTF-8 and BOM rejection | `src/canonical.ts:100`, `src/canonical.ts:108` | `test/canonical.test.ts:111`, `test/canonical.test.ts:117`, `test/canonical.test.ts:122` |
| Literal binary codec, canonical bits, prebounds | `src/encoding.ts:3`, `src/encoding.ts:10` | `test/encoding.test.ts:10`, `test/encoding.test.ts:27`, `test/encoding.test.ts:40`, `test/encoding.test.ts:54` |
| Native key profile, export/import, canonical SPKI | `src/signatures.ts:12`, `src/signatures.ts:49` | `test/signatures.test.ts:39`, `test/signatures.test.ts:53`, `test/signatures.test.ts:75`, `test/signatures.test.ts:105` |
| Key ID exact LF domain and decoded SPKI | `src/signatures.ts:71` | `test/signatures.test.ts:68` |
| Exact signed bytes and native P1363 cross-verification | `src/signatures.ts:27`, `src/signatures.ts:76` | `test/signatures.test.ts:130`, `test/signatures.test.ts:140`, `test/signatures.test.ts:145` |
| Binding and malformed rejection | `src/signatures.ts:84` | `test/signatures.test.ts:151`, `test/signatures.test.ts:156`, `test/signatures.test.ts:176`, `test/signatures.test.ts:188` |
| Synchronous caller-record snapshots | `src/signatures.ts:78`, `src/signatures.ts:87` | `test/signatures.test.ts:213`, `test/signatures.test.ts:222` |

## Executed verification

On 2026-10-13 with Node v26.5.0 / pnpm 10.29.3:

- Canonical test-first red: 11 missing-feature failures; green: 51 tests.
- Codec test-first red: 12 missing-feature failures; green: 38 tests.
- Signing test-first red: 33 missing-feature failures; green: 33 tests. A later native compressed-SPKI characterization plus mutation brings this suite to 34.
- Deliberately omitted sorting: 2 literal-order failures. Omitted parse equality: 10 expected rejection failures. Omitted purpose binding: 1 cross-purpose false/true failure. Omitted native SPKI equality: compressed-point import unexpectedly resolved. Restored every mutation.
- Final `pnpm test`: 281/281 (51 canonical + 38 codec + 34 signing + unchanged 158 history).
- `pnpm typecheck`, `pnpm build`, exact 20-export built-ESM smoke and `git diff --check`: passed. Smoke exercised canonical, codec, native key import/export, signatures and key ID.
- Seven-file engineering smell scan: no findings. No unrelated cleanup, runtime dependency, app or history change.

The package has no lint, typecheck:gate, integration or E2E scripts. Real cryptographic roundtrips run at the unit layer with native WebCrypto and independently Node crypto. Actual browser execution, lowest-supported-Node runtime compatibility, formal correctness/composition, external security review and complete authority readiness remain unverified. Independent spec then quality review is coordinator-owned.
