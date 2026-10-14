# Audience evidence commitment implementation plan

> **For agentic workers:** Use Superpowers subagent-driven development with test-driven development and two-stage review. Each code step starts with a failing test.

**Goal:** Commit private evidence values to an opaque audience scope and later verify only selected openings.

**Architecture:** Hash exact canonical value bytes under a fixed domain, a 32-byte audience identifier and a fresh 32-byte secret salt. The library creates an opaque one-use salt handle, whose bytes can be explicitly exported for private retention. Commitment creation accepts only that handle and returns only the public hash. No encryption or entitlement policy is inferred from this hash primitive.

**Tech stack:** Existing TypeScript, WebCrypto SHA-256 and Vitest package; no dependency.

## Ground truth

- `src/canonical.ts:90` encodes bounded canonical JSON; `src/hash.ts:20` computes SHA-256 with native WebCrypto.
- `src/encoding.ts:11` parses canonical base64url with a byte limit. `src/index.ts` holds explicit public exports.
- `docs/protocol-design.md` calls for independently salted commitments and selected openings; no commitment function exists yet.

## Journey and states

| Step | Caller | State before → after | Failure |
|---|---|---|---|
| Create | Approved client prepares a private evidence field | Value + audience → public commitment and private salt | Invalid audience/value or missing native randomness rejects |
| Publish | Product stores commitment in signed action | Unpublished → signed commitment | This library increment does not persist or sign it |
| Disclose | Authorized exporter sends value and salt | Hidden → selected opening | Wrong audience/value/salt/commitment rejects |

There is no route or DB state in this pure module. Audience authorization and private-body encryption remain separate later integration work.

## Changes

- `src/evidence-commitment.ts`: `createEvidenceSalt`, `exportEvidenceSalt`, `commitEvidence` and `verifyEvidenceOpening` with exact byte profile and strict input handling.
- `src/index.ts`: named exports and opaque `EvidenceSalt` type.
- `test/evidence-commitment.test.ts`: independent Node `createHash` oracle, native randomness, tampering, malformed and async snapshot behavior.
- `docs/evidence-commitment-profile.md`: byte contract, privacy and disclosure limits.

## Exact contract and proposed names

`audienceId` is exactly 64 lowercase hex characters representing an opaque 32-byte scope identifier selected by the caller. A public human-readable audience label should not be hashed here without an independent secrecy/identifier design. `createEvidenceSalt()` uses native randomness for 32 bytes and returns a frozen, own-property-free opaque `EvidenceSalt` handle. A module-private `WeakMap` holds the bytes, and type branding prevents ordinary TypeScript callers from constructing a handle. `exportEvidenceSalt(handle)` explicitly returns canonical unpadded base64url for the **private** opening. `commitEvidence(audienceId, value, handle)` accepts only a live handle made by this module, consumes it once, snapshots canonical value before its first `await`, and returns **only** the public hash. Callers export the opening before committing; subsequent reuse/export of a consumed handle rejects. `verifyEvidenceOpening(audienceId, value, saltString, commitment)` returns false on invalid runtime input and compares an independently recomputed hash. It snapshots value and salt before its first `await`. Publishing the hash or opaque handle cannot expose the salt through JSON serialization or the library canonicalizer.

Hash preimage: `0x04 || audienceId[32] || salt[32] || uint32be(canonicalValueByteLength) || canonicalBytes(value)`. `0x04` distinguishes map and history nodes. Canonical values are bounded at 1 MiB, so the 32-bit length is sufficient. Salt is generated with `globalThis.crypto.getRandomValues`, never `Math.random`. Keep the exported opening private until the audience receives it; a publicly disclosed salt permits offline guessing of a low-entropy value. These APIs do not encrypt the private body or prove that the caller may see it.

| Name | Honest responsibility | Name strain / decision |
|---|---|---|
| `createEvidenceSalt` | Generate one opaque random salt handle | One concept; keep |
| `exportEvidenceSalt` | Explicitly reveal salt for private storage | One concept; keep |
| `commitEvidence` | Make one salted scoped public hash | One concept; keep |
| `verifyEvidenceOpening` | Check one presented opening | One concept; keep |
| `EvidenceSalt` | Opaque one-use handle | Single role; keep |

## Test-first steps

1. Write an independent Node SHA-256 oracle for the exact preimage and first failing test for `createEvidenceSalt`, `exportEvidenceSalt` and `commitEvidence` of a literal value. Run `pnpm exec vitest run test/evidence-commitment.test.ts`; observe missing-export failure. Implement minimal native salt handle and public hash, confirm oracle match.
2. Add failing tests for two handles producing independent 32-byte openings and commitments. Assert `JSON.stringify(handle)` is `{}`, `canonicalJson(handle)` has no salt, and serializing the public hash has no salt. Reject all-zero string or forged object as `commitEvidence` input, and second use/export of a consumed handle. Reject invalid audience and unsupported canonical values. Implement minimal validation/consumption.
3. Add failing tests for `verifyEvidenceOpening`: valid selected opening; wrong audience/value/salt/hash; malformed and noncanonical salt; getter/cycle/oversize value. Implement minimal verification with false on malformed inputs.
4. Add a failing pre-await mutation test for caller-owned value on creation and verification. Canonicalize synchronously before any await. Deliberately remove audience binding or change the byte-length encoding, observe a failing oracle/tamper test, restore.
5. Run focused and full `pnpm test`, `pnpm typecheck`, `pnpm build`, built ESM smoke and `git diff --check`; review touched files, document exact limits and commit. Request separate specification and code-quality reviews before publishing.

## Review correction, 2026-10-14

The first implementation returned enumerable `{ commitment, salt }`. Quality review and independent reproduction showed that blindly serializing this result publishes the salt and permits offline guessing of low-entropy values. The second implementation separated salt generation from the public hash but accepted a caller-supplied all-zero salt, which independently reproduced offline guessing. The final planned API above avoids both caller-supplied salt and combined public/private return. Test each failure mode before replacement, then rerun specification and quality review.

The implementation commits are `9a4db40` for the initial preimage, `a9d8b32` for the first API separation and `5af71b6` for the opaque one-use handle. The implementer reported observed red tests and deliberate mutations; those historical terminal runs are not independently reconstructible from the combined commits. Final specification and quality reviews accepted `5af71b6`; the quality reviewer reproduced rejection of all-zero/forged/stale handles, safe public serialization, exact hash oracle agreement and one-success concurrent consumption. Parent gates passed 393 package tests, typecheck, build and compiled ESM opening/zero-salt checks. A selected compiled-module smoke additionally passed 22 checks each in Chromium 149.0.7827.55, Firefox 151.0 and WebKit 26.5, including map presence/absence and browser-to-Node commitment opening. This is not the full unit suite in browsers or a public portable test harness; minimum Node 22 execution is unverified. This increment alone does not encrypt private bodies or decide audience access.

## Principles, smells and verification

One module owns this commitment profile; reuse existing canonical/codec/hash helpers. Keep encryption, authorization and evidence transport outside this primitive. No general commitment framework or arbitrary salt length. The caller owns private salt storage. Review new names before implementation and keep touch-file cleanup separate. Package gates are test/typecheck/build and compiled import; the app's lint/typecheck:gate/integration gates do not apply until app source changes.
