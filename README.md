# 1bridge authority

Pure TypeScript primitives for workspace-scoped authority and independently checkable governance evidence. Experimental development; no production audit or formal verification is claimed.

Implemented primitives: RFC 9162 Merkle history, restricted canonical JSON, bounded canonical base64url, and purpose-bound native P-256 signatures/key import/export. Authenticated directory, authority policy, completion receipts, blind proof-access tokens and storage adapters remain subsequent increments. This experimental package is not ready for 1bridge integration.

## Development

Use Node 22 or later and pnpm 10.29.3:

```sh
pnpm install --frozen-lockfile
pnpm test
pnpm typecheck
pnpm build
```

Core modules use native WebCrypto with no runtime dependencies. Merkle proofs authenticate a supplied history; they cannot discover an entirely hidden history without independent evidence. Signature authorization and current-state discovery are separate layers.

See docs/history-profile.md and docs/encoding-signature-profile.md for construction/test coverage and limits. Development verification passes 284 unit tests, typecheck and build; selected compiled-module interoperability smoke checks also pass in Chromium 149, Firefox 151 and WebKit 26.5 with Node 26.5. These are not full browser policy/workflow evaluations or a formal security proof.
