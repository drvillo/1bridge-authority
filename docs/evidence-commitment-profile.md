# Evidence commitment profile

`createEvidenceSalt()` returns a fresh private salt. `commitEvidence(audienceId, value, salt)` accepts that salt and returns **only** the public commitment hash. The caller supplies an opaque `audienceId` as exactly 64 lowercase hexadecimal characters, encoding 32 bytes. A different audience ID or salt changes the hash preimage, binding each commitment to that scope and opening. The caller chooses and validates the audience scope; this library does not grant access to it.

The salt generator uses native `crypto.getRandomValues` for 32 bytes, encoded as canonical, unpadded base64url (43 characters). `commitEvidence` rejects malformed or noncanonical supplied salts and canonicalizes `value` with `canonicalBytes`. The commitment is a lowercase 64-character hexadecimal SHA-256 digest of exactly:

```text
04 || audienceId[32] || salt[32] || uint32be(valueLength) || canonicalBytes(value)
```

`04` is one domain byte. Bracketed sizes are raw byte counts, `||` means byte concatenation, and `valueLength` is the number of canonical UTF-8 bytes, encoded as a four-byte unsigned integer in network byte order. Thus the preimage has 69 fixed bytes followed by the canonical value bytes. The domain byte separates this profile from the existing history and ordered-map hash domains. `canonicalBytes` limits values to 1 MiB and rejects unsupported JSON shapes and values; the four-byte length covers that bound. Commitment creation and opening verification capture the canonical bytes and salt before their first asynchronous hash operation, so changing a caller-owned value object while hashing cannot change the result.

Keep the salt outside the public payload. For example:

```ts
const salt = createEvidenceSalt()
const commitment = await commitEvidence(audienceId, value, salt)
const publicPayload = { audienceId, commitment }
// Retain { audienceId, value, salt, commitment } in a protected opening store.
```

Only a selected disclosure sends the private opening `{ audienceId, value, salt, commitment }` to its authorized recipient. `verifyEvidenceOpening(audienceId, value, salt, commitment)` recomputes the preimage. It returns `true` only for an exact match and `false` for malformed runtime input, including a malformed audience ID or commitment, a salt that is not exactly 32 decoded bytes of canonical unpadded base64url, or a value outside the canonical profile. Its result verifies an opening under the **supplied** audience ID and commitment; the caller must obtain a trusted commitment through the protocol that uses it.

Keep the salt private until a selected opening is disclosed to an authorized audience. Publishing it permits offline guessing of low-entropy values. A commitment does not encrypt the evidence body, conceal metadata already published alongside it, or decide who may receive an opening. Storage, body encryption, audience authorization, and disclosure transport belong to the integrating product.
