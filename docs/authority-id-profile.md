# Product UUID and actor-subject mapping v1

`authorityId(kind, uuid)` maps a product UUID into a lowercase 64-character SHA-256 authority ID. The permitted `kind` values are exactly `workspace`, `vault`, `membership`, `membership-key-row` and `operation`. Its input accepts the eight-four-four-four-twelve hexadecimal UUID shape with literal hyphens, folding A–F to lowercase. It rejects braces, URNs, whitespace, other punctuation, nonhex characters and invented kinds. It deliberately does not require a particular UUID version or variant.

The wire formula is `SHA256(UTF8('1bridge.authority/v1/id/' + kind + '\n' + lowercaseUuid))`. The fixed test UUID `550e8400-e29b-41d4-a716-446655440000` maps to:

| Kind | SHA-256 hex |
|---|---|
| `workspace` | `9388d79f479cf64a08567eafc736f6811110e0238bd557e8cc24bce53cb82f2c` |
| `vault` | `398a28f25c45fd8cdf8a7b52004ce06a3ac580e1d5c62c173d59c3b82293ac9c` |
| `membership` | `1cda0b825cdef47e69bcca0a337807edbceb5fede4a821e1f92cfac5d13531ce` |
| `membership-key-row` | `8999536b6cedb907e94d2d9c29d2800e53711b398c7e63f6ace7484af12aaca0` |
| `operation` | `8e0b1cef28645380989ecbfb5573fc7b5372ccaafd5c7ce4e5e2c9a0050513d1` |

`authoritySubjectId({workspaceId,membershipId,actorKeyId})` binds already-mapped workspace and membership IDs to the actor's P-256 signing-key ID. Each is lowercase 64-hex. The record must have exactly those three enumerable data fields on an ordinary or null-prototype object; accessors, symbols, inherited custom prototypes, extras and malformed hashes reject. The wire formula is `SHA256(UTF8('1bridge.authority/v1/actor-subject\n') || canonicalBytes(record))`, using the library's sorted-key canonical JSON. IDs of 64 `a`, `b` and `c` characters respectively yield `cf234a9907485fb3707c0b3a0992d71091eb03dda20771b18ce9ca4589791c44`.

These values are deterministic and pseudonymous, not secret. Anyone knowing a UUID can test it against a mapped ID. A hash does not establish product ownership, current membership, key possession or authorization. A second device reusing the same actor signing key has the same subject. The application must perform those operational checks and compare opened rows with the signed claims. This module does not modify app IDs or database rows.

## Verification record

`test/authority-ids.test.ts` failed first because the module was absent. Node's independent `createHash('sha256')` produced the fixed vectors. Seven focused tests passed after implementation, including every kind, uppercase normalization, cross-kind separation, subject-field changes and adversarial syntax/record cases. Mutating the UUID domain prefix made the fixed UUID test fail; mutating the actor-subject domain prefix made its fixed-vector test fail. Both mutations were restored.

The initial direct-module run of `pnpm test` passed 486 tests with one pre-existing todo; `pnpm typecheck` and `pnpm build` passed. Direct built-module browser smoke passed fixed vectors and invalid-kind rejection in Chromium, Firefox and WebKit. The package-root export was then added after observing the same seven tests fail on a missing root function; all seven passed through the root import. A fresh compiled package-root browser smoke passed both fixed ID/subject vectors in Chromium, Firefox and WebKit. No package lint script exists. The app's lint, typecheck gate, full test, persistence and navigation gates do not apply to this pure-library increment. Cross-repository app/observer vectors remain integration work.
