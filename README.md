# 1bridge authority

Pure TypeScript primitives for workspace-scoped authority and independently checkable governance evidence. Experimental development; no production audit or formal verification is claimed.

The first increment implements the RFC 9162 Merkle history layer. Authenticated directory, authority policy, completion receipts, blind proof-access tokens and storage adapters remain subsequent increments. This initial package is not ready for 1bridge integration.

## Development

Use Node 22 or later and pnpm 10.29.3:

```sh
pnpm install --frozen-lockfile
pnpm test
pnpm typecheck
pnpm build
```

Core modules use native WebCrypto with no runtime dependencies. Merkle proofs authenticate a supplied history; they cannot discover an entirely hidden history without independent evidence. Signature authorization and current-state discovery are separate layers.

See docs/history-profile.md for construction/verification coverage and limits.
