# 1bridge authority

Pure TypeScript primitives for workspace-scoped authority and independently checkable governance evidence. Experimental development; no production audit or formal verification is claimed.

Implemented primitives: RFC 9162 Merkle history and append frontier, deterministic ordered-map presence/absence proofs, restricted canonical JSON and base64url, purpose-bound native P-256 signatures, audience-scoped salted evidence commitments, signed governance checkpoints, pinned customer-root authority policy/replay, and RFC 9474 blind proof-access tokens. Completion receipts, private evidence-body disclosure and storage adapters remain subsequent increments. This experimental package is not ready for 1bridge integration.

## Development

Use Node 22 or later and pnpm 10.29.3:

```sh
pnpm install --frozen-lockfile
pnpm test
pnpm typecheck
pnpm build
```

Core modules use native WebCrypto with no runtime dependencies. Merkle proofs authenticate a supplied history; they cannot discover an entirely hidden history without independent evidence. Signature authorization and current-state discovery are separate layers.

See the profile documents under `docs/` for construction, test coverage and limits. The package test, typecheck and build gates pass on Node 26.5. Selected compiled-module browser smoke checks exercised the portable primitives, pinned authority anchor and blind-token round trips in Chromium, Firefox and WebKit. These are not full browser policy/workflow evaluations or a formal security proof. In particular, product issuance eligibility, cohort certification and atomic one-use redemption are not implemented by this library.
