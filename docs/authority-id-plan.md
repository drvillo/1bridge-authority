# Product UUID and actor-subject mapping plan

> Planned pure-library mapping increment before 1Bridge app integration. It defines one byte contract shared by the app, independent observer fixtures and exported evidence. No existing app ID or database row changes.

## Ground truth

- `src/authority-lifecycle.ts` uses lowercase 64-hex `Hash` values for feed/workspace, subject, scope and signing-key identities. `src/recipient-key.ts` uses the same type for workspace, membership and membership-key-row IDs. The library currently does not map app UUIDs to those hashes.
- The app's workspace, vault, membership and membership-key-row primary keys are UUID strings (`ubo-guard/webapp/prisma/schema.prisma:66-67,964-990,1080-1102`). Current authority integration is only a plan, not app behavior.
- The app has no verified persisted per-device UUID in the D1 journey traced so far. The proposed actor subject therefore derives from workspace, membership and a distinct P-256 actor signing-key ID, without claiming existing device identity. A second device that reuses a signing key cannot be distinguished by this mapping.

## Journey and states

| Step | Caller | Before → after | Failure |
|---|---|---|---|
| Map model ID | App/fixture | Valid UUID and fixed kind → domain-separated 64-hex authority ID | Non-UUID, unexpected kind or alternate punctuation rejects |
| Enroll actor | Customer-root ceremony | Mapped workspace/membership and actor signing-key ID → stable subject ID for root-signed binding | Changed member/workspace/key yields a different subject; malformed hash rejects |
| Cross-check | Browser/observer | Exact published UUID openings, if audience-authorized → same mapped IDs and subject | Mapping mismatch rejects the opening; hash alone does not reveal real-world identity |

## Wire contract

`authorityId(kind, uuid) = SHA-256(UTF8('1bridge.authority/v1/id/' + kind + '\n' + lowercaseUuid))`. `kind` is exactly one of `workspace`, `vault`, `membership`, `membership-key-row`, `operation`. `uuid` matches eight-four-four-four-twelve hexadecimal groups with literal hyphens. Uppercase A–F folds to lowercase; braces, URNs, whitespace, missing hyphens or non-hex reject. The mapping does not imply UUID version/variant validity or ownership. `operation` maps the app's preallocated operation UUID to the signed 64-hex operation ID.

`authoritySubjectId({workspaceId,membershipId,actorKeyId}) = SHA-256(UTF8('1bridge.authority/v1/actor-subject\n') || canonicalBytes({workspaceId,membershipId,actorKeyId}))`. Inputs are already mapped lowercase 64-hex values except `actorKeyId`, which is the library's P-256 `signingKeyId`. Accept only an exact plain object with three enumerable data fields; reject getters, extra keys and malformed hashes. The canonical JSON encoder supplies fixed key order. Do not use a raw UUID or arbitrary string concatenation for subjects.

These IDs are deterministic and pseudonymous. Anyone who knows a UUID can test it against a published mapped ID; they are not secret or an anonymity construction. The app still checks actual operational workspace/membership ownership, current role and exact recipient-key row; the mapping alone grants no permission.

## Changes and proposed names

| Path/name | Responsibility | Decision |
|---|---|---|
| `src/authority-ids.ts` `authorityId` | Map one UUID under one fixed app role | Keep; no generic ID registry |
| `src/authority-ids.ts` `authoritySubjectId` | Bind mapped workspace/member and P-256 actor key | Keep; actor identity, not device authentication |
| `src/index.ts` | Export both browser-safe helpers | Keep after replay's concurrent index edit settles |
| `test/authority-ids.test.ts` | Fixed vectors and invalid-shape/cross-kind tests | Lowest layer |

## Test plan

1. Write missing-export tests for fixed independent Node SHA-256 vectors and uppercase normalization; observe red before implementation. Check every fixed kind and cross-kind separation.
2. Test exact subject shape, changed workspace/member/actor key, invalid UUID punctuation/version-neutral format, accessor/extra/sparse data, malformed hash and prototype attempts. Assert domain outcome and known bytes, not self-consistency alone.
3. Implement with native WebCrypto/`sha256` and existing `canonicalBytes`; no dependency. Break one domain prefix or kind check and watch targeted fixed-vector test fail, then restore.
4. Run full package tests, typecheck, build, browser root import and `git diff --check`; obtain independent spec/quality review. The later app/observer cross-repo fixture must recalculate the same vectors from actual UUID rows before protected claims.

## Principles and verification

SRP: this module maps syntax/identity bytes only; lifecycle authorizes bindings and the app checks ownership. DRY: shared helper and fixed vectors prevent three repos from drifting. YAGNI: no device table or generic policy registry. KISS: two domain-separated SHA-256 formulas. Boy Scout cleanup is limited to touched files, separate from behavior change. This increment does not touch app source, so app gates do not apply yet.
