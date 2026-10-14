# Unlinkable proof-access token implementation plan

> Implementation record for the portable blind proof-access primitive. Separate specification and quality reviews accepted the implementation; package tests, typecheck, build and selected Node/browser round trips passed on 2026-10-14. Product issuance eligibility, cohort certification and one-use redemption remain future integration work.

**Goal:** Give an eligible client one unlinkable, one-use proof-read credential without making an approval anonymous. The cryptographic library provides RFC 9474 ordinary blind RSA; the product later checks eligibility at issuance and atomically consumes a nullifier at redemption. An independently trusted customer certificate fixes what the issuer key is allowed to admit.

**Approved direction:** The user requested blind signatures specifically for unlinkable proof-access tokens and attributable approvals, with a pure TypeScript library using the 1bridge stack. The public API selects one RFC profile and has no runtime dependency. A Node-only native private operation stays outside the browser root export. This is additive to the existing P-256 governance signatures; it never signs governance changes.

## Ground truth

- [RFC 9474 §§4–5 and Appendix A.1](https://www.rfc-editor.org/rfc/rfc9474.html) defines RSABSSA-SHA384-PSS-Randomized: 32-byte randomized preparation prefix, SHA-384/MGF1, 48-byte PSS salt and exact 4096-bit sample vectors. [RFC 8017 §9.1.1](https://www.rfc-editor.org/rfc/rfc8017.html#section-9.1.1) supplies EMSA-PSS encoding.
- [Reported RFC 9474 erratum 9089](https://errata.rfc-editor.org/eid9089/) changes the printed Blind call from `bit_len(n)` to `bit_len(n)-1`. The corrected value is required for native RSA-PSS verification; record its reported status rather than presenting it as a formally updated RFC.
- `src/index.ts` currently exports browser-safe primitives only; `package.json` currently has no runtime dependencies and only a `.` import. `src/evidence-commitment.ts` shows a private one-use handle pattern, while `src/encoding.ts` supplies canonical base64url.
- A read-only Node 26.5.0 experiment reconstructed the RFC A.1 generic RSA private key and matched its 512-byte `blind_sig` with `privateEncrypt(RSA_NO_PADDING)`; native WebCrypto verified the final signature. This experiment is a design lead, not a repository conformance test or Vercel deployment result. A `rsa-pss` KeyObject rejected that raw private operation; require a dedicated generic `rsa` key used only for this profile.
- The product has no blind-token issuance/redemption storage or cohort certificates yet. This increment cannot claim unlinkability against a one-user cohort, login/network correlation, or replay resistance without the later transactional nullifier store.

## Journey and states

| Step | Caller | Before → after | Failure |
|---|---|---|---|
| Pin issuer | Customer/client | Customer-certified shared cohort key and scope → accepted public key | Invalid certificate/key/scope rejected by later authority policy; no per-user key |
| Blind | Browser client | Fresh nonce and native randomness → blinded representative plus opaque one-use state | Bad key or random/inverse rejects without emitting request |
| Issue | Product Node route after attributable eligibility check | One authenticated issuance entitlement → raw blinded RSA signature | Malformed representative/key rejects; issuer cannot see token nonce |
| Finalize | Browser client | Blinded signature and transient state → verified token | Wrong response/key/profile rejects; one-use state consumed |
| Redeem | Product proof-read route | Token plus certified cohort scope → audience-limited proof read; nullifier consumed in one DB transaction | Bad cert/signature/expiry/audience or spent nullifier rejects |

Approaches considered: a bearer token minted in plaintext links issuance to redemption; a user-specific blind issuer key identifies the user despite blinding. The selected shared certified cohort separates attributable eligibility from anonymous redemption. The signed message has **no client-chosen scope claim**: one dedicated signing key and one customer-certified cohort scope fix the workspace, capability, audience and expiry window. The same key must never be certified for a second scope or re-certified for a later window; renewal generates a new key. Redemption verifies the certificate for the *expected* scope and key, rather than accepting any certificate that happens to name a key that validates the signature. This is an app integration invariant and requires negative cross-scope and renewal-replay tests there. Network/timing correlation remains a separate deployment threat.

## Wire/API contract and files

Select exactly `RSABSSA-SHA384-PSS-Randomized`, 4096-bit RSA modulus and public exponent 65537, SHA-384/MGF1, 48-byte PSS salt, 32-byte PrepareRandomize prefix, `emBits = modBits-1`. Do not expose algorithm-selection knobs. The browser produces a fixed message of ASCII `1bridge.authority/v1/proof-access\n` followed by 32 random nonce bytes; it prepends a further 32 random bytes for RFC PrepareRandomize. The token holds only canonical base64url `preparedMessage` and fixed-width `signature`. The 32-byte prefix and nonce are unrelated native random draws. Never put a user ID, issuance ID, selected proof ID or customer-chosen scope in the signed message.

`src/blind-proof-access.ts` owns browser-safe key import, randomness, PSS encoding, public modular arithmetic, blinding, finalization, verification and nullifier hash. It may use a private `src/blind-rsa.ts` helper for RFC arithmetic/vector injection, but that helper is not a package export. Import the public SPKI as an extractable verify-only RSA-PSS/SHA-384 `CryptoKey`, export its *public* JWK to snapshot modulus `n` and exponent `e`, and associate that snapshot with the exact returned key in a private WeakMap. `blindProofAccess` and `verifyProofAccess` reject foreign or mismatched `CryptoKey` objects; native PSS verification uses the same associated key. `src/blind-proof-access-server.ts` owns Node-only `KeyObject` validation and `privateEncrypt(RSA_NO_PADDING)` with native public-operation self-check. `src/index.ts` exports only browser-safe names. `package.json` adds a `./server` conditional export pointing at a separate built Node module, not importing Node crypto from `.`. `test/blind-proof-access.test.ts` and `test/blind-proof-access-server.test.ts` cover vectors and misuse. `test/fixtures/rfc9474-a1.json` contains only the exact official vector fields needed, with source citation. `docs/blind-proof-access-profile.md` gives the profile, custody, cohort and limitations.

Public names: `importProofAccessPublicKey(spkiBase64url):Promise<CryptoKey>` validates 4096/65537 and RSA-PSS/SHA-384 verify-only; `blindProofAccess(publicKey):Promise<{blindedMessage:string,state:ProofAccessBlindState}>`; `finalizeProofAccess(state,blindSignature):Promise<ProofAccessToken>` consumes state and verifies before returning; `verifyProofAccess(token,publicKey):Promise<boolean>` validates exact fields/message profile and native PSS; `proofAccessNullifier(token):Promise<Hash>` domain-separated hash of the exact prepared message after structure validation. Server entry point: `signBlindedProofAccess(blindedMessage,privateKey:KeyObject):string` accepts only dedicated generic RSA-4096/65537 keys and exact-width representatives in `(0,n)`, performs native private operation and public self-check. The library does not decide whether a key is properly customer-certified; callers must verify that separate signed certificate before accepting it.

Draw the blind factor uniformly from `[1,n)` with rejection sampling on fresh native random bytes: reject samples outside the interval and retry noninvertible factors, as specified in RFC 9474 §4.2. Do not reduce random bytes modulo `n`, which biases the distribution. `ProofAccessBlindState` is opaque, frozen and privately held (for example a module-private WeakMap) so JSON/canonical JSON do not expose the inverse or prepared message. An invalid finalization attempt consumes the handle; the client must start a new issuance if it loses the response. The client must retain this state until finalization; a browser reload loses it. Do not add a serialized secret-state format in this increment.

## Proposed names and strain

| Name | Responsibility | Decision |
|---|---|---|
| `importProofAccessPublicKey` | Accept one fixed-profile issuer key | Keep; no generic RSA import |
| `blindProofAccess` | Generate one blinded request and transient state | Keep; fixed message avoids coupled scope concerns |
| `finalizeProofAccess` | Unblind and verify one response | Keep; RFC operation |
| `verifyProofAccess` | Check exact token and signature | Keep; no authorization claim |
| `proofAccessNullifier` | Derive stable one-use DB key | Keep; DB consume is separate |
| `signBlindedProofAccess` | Native private RSA operation in Node | Keep; server-only entry point |

Private helpers such as `mgf1`, `emsaPssEncode`, `modPow`, `modInverse`, `os2ip`, `i2osp`, `snapshotToken`, and `snapshotKey` each have one arithmetic/validation role. Avoid a generic credential framework or second token algorithm.

## Test-first plan

1. Add missing-export tests and observe red. Use RFC 9474 A.1 to compare `preparedMessage`, EMSA-PSS encoding, blinded message, blinded signature and finalized signature byte for byte under *internal test-only* fixed `msg_prefix`, PSS salt and `r = inv^-1 mod n`; the RFC `msg` is arbitrary bytes and does not match the product's fixed message. First implement public arithmetic/PSS. Deliberately change `emBits` to `modBits` and see vector/native verify fail; restore.
2. Add browser-safe fixed-format API tests for two independently issued tokens, wrong/foreign key, changed prepared bytes/signature, extra/missing/accessor fields, malformed base64url, wrong key size/exponent/algorithm, noninvertible factors, rejection of out-of-range random candidates rather than biased modulo reduction, representatives `>=n`, mutation across await and one-use state. Implement minimum API. Verify no inverse leaks through JSON/canonical encoding.
3. Add server tests using RFC A.1 private key and a freshly generated **test-only** dedicated RSA key. Observe missing server export red. Reject wrong key type/size/exponent, malformed width/zero/out-of-range values; run native public self-check and correct request round trip. Never use JS private exponent arithmetic in production.
4. Add focused nullifier tests: same token gives same nullifier, distinct prepared messages differ, malformed token rejects. Mutation of nullifier domain must fail. DB uniqueness and issuance accounting belong to later app integration tests, not this pure module.
5. Run full package tests/typecheck/build, exact root and `./server` compiled exports, selected Chromium/Firefox/WebKit issuance/finalization, and Node 22/24 or target Vercel runtime smoke where available. Record what could not be tested. Request independent spec and quality review before publication.

## Principles, smells and verification

SRP: browser public proof, Node private operation, and product-specific certificate/eligibility/redemption are separate. DRY: one fixed RFC profile and existing encoding/hash utility. KISS/YAGNI: no alternate RSA variants, no key generation service, no X.509 certificates and no generic claims parser. The server key MUST NOT be reused for other protocols or encoding profiles ([RFC 9474 §6.2](https://www.rfc-editor.org/rfc/rfc9474.html#section-6.2)), **or for any other certified scope or validity window**; an app transaction must prohibit duplicate/overlapping certification and renewal must rotate the key. The verifier must select the valid key of its expected issuer/scope ([RFC 9474 §7.5](https://www.rfc-editor.org/rfc/rfc9474.html#section-7.5)). Native private operations still require deployment side-channel assessment; functional tests are not proof of secrecy. Full unlinkability needs a cohort of multiple indistinguishable users, privacy-preserving redemption route behavior, and no issuance/redemption metadata join. Replay protection needs a database transaction. No app source changes in this increment, so its lint/typecheck:gate/integration/E2E gates do not apply yet.
