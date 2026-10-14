# Signed governance checkpoint profile

This package's checkpoint is a provider-signed claim about one feed head and one authority-map root. A caller must pin the feed ID and the provider's P-256 public key independently. A public key supplied beside an untrusted checkpoint is not a trust anchor.

## Wire format

`GovernanceCheckpoint` has exactly these data fields:

| Field | Profile |
| --- | --- |
| `version` | Literal `1` |
| `feedId` | Opaque 32-byte lowercase hexadecimal feed identifier |
| `size` | Nonnegative safe integer history size, excluding negative zero |
| `historyRoot` | Lowercase hexadecimal RFC 9162 SHA-256 tree root |
| `authorityRoot` | Lowercase hexadecimal authority-map root |
| `policyEpoch` | Nonnegative safe integer, excluding negative zero |
| `signerKeyId` | Lowercase hexadecimal ID of the signing public key |
| `previous` | `null` for size zero; otherwise a lowercase hexadecimal checkpoint statement ID |

For size zero, `historyRoot` must be SHA-256 of empty bytes (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`) and `previous` must be `null`. The signed envelope is exactly `{statement, signature}`. Unknown fields, symbols, missing fields and accessors reject. The signature is a canonical unpadded base64url encoding of the native 64-byte IEEE-P1363 P-256 signature.

`signCheckpoint(statement, keyPair)` checks the statement and the supplied key pair, confirms that `signerKeyId` equals `signingKeyId(keyPair.publicKey)`, and signs the canonical statement under the existing `history.checkpoint` purpose. It returns an owned statement snapshot. The public and private keys must match. `verifyCheckpoint(signed, trustedPublicKey)` returns `false` for malformed input, a signer-ID mismatch or a bad signature.

`checkpointHash(statement)` hashes the UTF-8 prefix `1bridge.authority/v1/checkpoint-id\n` followed by the canonical statement bytes with SHA-256. Its value identifies the statement independent of randomized signature bytes; it is neither a timestamp nor a receipt.

## Extension verification

`verifyCheckpointExtension(oldSigned, newSigned, proof, trustedPublicKey)` checks both signatures under the same independently trusted key; equal feed and signer IDs; strictly increasing size; nondecreasing policy epoch; `newSigned.statement.previous === checkpointHash(oldSigned.statement)`; and an RFC 9162 consistency proof from the old `(size, historyRoot)` pair to the new pair. It returns `false` on malformed input or any failed check. The caller retains the previously trusted signed head. The proof and both heads are snapshotted before the first asynchronous check.

`previous` names the immediately preceding **signed checkpoint statement**, even when a checkpoint covers more than one leaf. If several signed checkpoints were published while a client or observer was offline, it must retrieve and verify each intervening checkpoint in order. A direct retained-head-to-latest comparison fails when the latest head points to an intermediate checkpoint. The future pull feed must therefore retain those signed checkpoints and their associated consistency material; a current-head endpoint alone is insufficient for backlog recovery.

The verifier rejects signer rotation. A later explicit authority transition must define rotation. A valid extension confirms that the signed history commitment retained its old prefix. It does not prove that the provider published every leaf, that the authority map is correct, that the policy epoch changed lawfully, or that any action was authorized. Those claims require independently held evidence and full authority replay. This library module performs no database, network, release-blocking or observer operation.

## Verification record

The lowest-layer unit suite is `test/checkpoint.test.ts`. Its first run failed on the missing exports (18 expected failures). Intentional mutations of the checkpoint-ID domain, predecessor comparison, consistency comparison and data-descriptor getter guard each caused the relevant unit test to fail, then were restored.

On 2026-10-14, the focused suite passed 18/18; `pnpm test` passed 418/418; `pnpm typecheck`, `pnpm build`, the scoped advisory smell scan and the staged diff check passed. A selected compiled ESM smoke passed 27 checks each in Chromium 149.0.7827.55, Firefox 151.0 and WebKit 26.5, verifying Node-to-browser and browser-to-Node checkpoint signatures plus a browser-signed 0→1 extension. This smoke does not replace the full unit suite in browsers or a formal security assessment. The source uses the existing canonical encoder, native signer and RFC history verifier; it adds no runtime dependency.
