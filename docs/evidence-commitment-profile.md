# Evidence commitment profile

`commitEvidence(audienceId, value)` returns `{ commitment, salt }`. The caller supplies an opaque `audienceId` as exactly 64 lowercase hexadecimal characters, encoding 32 bytes. A different audience ID or salt changes the hash preimage, binding each commitment to that scope and opening. The caller chooses and validates the audience scope; this library does not grant access to it.

The function canonicalizes `value` with `canonicalBytes` and generates 32 fresh bytes with native `crypto.getRandomValues`. It encodes the salt as canonical, unpadded base64url (43 characters). The commitment is a lowercase 64-character hexadecimal SHA-256 digest of exactly:

```text
04 || audienceId[32] || salt[32] || uint32be(valueLength) || canonicalBytes(value)
```

`04` is one domain byte. Bracketed sizes are raw byte counts, `||` means byte concatenation, and `valueLength` is the number of canonical UTF-8 bytes, encoded as a four-byte unsigned integer in network byte order. Thus the preimage has 69 fixed bytes followed by the canonical value bytes. The domain byte separates this profile from the existing history and ordered-map hash domains. `canonicalBytes` limits values to 1 MiB and rejects unsupported JSON shapes and values; the four-byte length covers that bound. Both functions capture the canonical bytes before their first asynchronous hash operation, so changing a caller-owned object while hashing cannot change the result.

`verifyEvidenceOpening(audienceId, value, salt, commitment)` recomputes that preimage. It returns `true` only for an exact match. It returns `false` for malformed runtime input, including a malformed audience ID or commitment, a salt that is not exactly 32 decoded bytes of canonical unpadded base64url, or a value outside the canonical profile. Its result verifies an opening under the **supplied** audience ID and commitment; the caller must obtain a trusted commitment through the protocol that uses it.

Keep the salt private until a selected opening is disclosed to an authorized audience. Publishing it permits offline guessing of low-entropy values. A commitment does not encrypt the evidence body, conceal metadata already published alongside it, or decide who may receive an opening. Storage, body encryption, audience authorization, and disclosure transport belong to the integrating product.
