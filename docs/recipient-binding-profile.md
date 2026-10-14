# Recipient-key claim and authority binding v1

This pure TypeScript profile commits an existing 1bridge X25519 recipient public key to a customer-root-signed actor binding. It does not enroll an app membership, prove X25519 private-key possession, enforce database atomicity, or select a live recipient row. Those are app integration duties.

`RecipientKeyClaim` is the exact ordinary data record `{version:1,workspaceId,membershipId,membershipKeyRowId,membershipKeyVersion,keySuite:'x25519',keyId,publicKey}`. The three IDs are lowercase 64-character authority-domain hashes. `membershipKeyVersion` is a positive safe integer for the recipient row, independent of the authority-binding version. Extra, omitted, accessor, symbol or malformed fields are rejected.

`publicKey` is exactly `v3.x25519.` followed by canonical unpadded base64url of 32 nonzero raw bytes. `keyId` is canonical unpadded base64url of SHA-256 of those bytes and is exactly 43 characters. The helper verifies both with native WebCrypto; the app also checks the row using its existing `@drvillo/webcrypto-seal` helper. The claim hash is lowercase hex `SHA256(UTF8('1bridge.authority/v1/recipient-key\n') || canonicalBytes(claim))`.

Fixed cross-repository vector, generated with the app's `formatPublicKey`, `computeKeyId` and `validatePublicKeyFingerprint` on raw bytes `01 02 ... 20`, with the hash independently computed using Node SHA-256 over the sorted canonical claim bytes:

```json
{"version":1,"workspaceId":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","membershipId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","membershipKeyRowId":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","membershipKeyVersion":7,"keySuite":"x25519","keyId":"riFsLvUkejeCwTXvonmj5M3GEJQnD10r5YxiBLemEsk","publicKey":"v3.x25519.AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"}
```

The hash is `70fc6416d6c82ed81fa18f4ae499b25adfebee21bf6abca56596b42b3e56660c`. Since canonical JSON orders keys, the displayed claim field order does not affect that hash.

An active binding carries `recipientKeyCommitment: Hash | null` inside its exact root-signed revision and ordered-map value hash. A tombstone carries no current recipient claim. A customer-root-signed version update can replace the commitment while retaining the actor P-256 key. The app must open the claim from the exact active `WorkspaceMembershipKey` row and compare every field and hash before using that key for a protected recipient. The app adapter maps UUIDs to authority IDs; the generic library accepts only the already-mapped IDs. Existing app key-possession challenges remain mandatory. This wire change is pre-release: no deployed V1 authority bindings need migration yet.

## Verification record

The focused tests failed before implementation because the claim helper was absent and the binding rejected the new exact field. The finalized suite checks the fixed app-wire vector, scope/row/version changes, malformed envelopes and fingerprints, missing and extra fields, null bindings, root-signed commitment updates, and signed-revision tampering. Temporarily replacing the signed binding commitment with null made the commitment/map test fail; changing the claim-hash domain prefix made the fixed-vector test fail. Both mutations were restored. `pnpm test` passed 460/460; `pnpm typecheck` and `pnpm build` passed. A built-module browser smoke passed the recipient vector and fingerprint rejection in Chromium, Firefox and WebKit (31 checks per engine). The advisory smell scan reported no findings. This package has no lint, `typecheck:gate`, persistence-integration or navigation-E2E scripts; those gates are not claimed here. Independent review and application-level row/transaction tests remain separate work.
