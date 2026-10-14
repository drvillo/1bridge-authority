# Pinned mixed-history replay increment plan

> Planned portable-library increment. The existing `verifyGovernanceAction` and `verifyReceiptInclusion` functions check narrower claims. Until the API in this plan exists and the observer calls it, neither repo has full witnessed-governance verification.

## Ground truth

- `src/authority-lifecycle.ts` verifies an independently pinned, dual-signed anchor and folds customer-signed revisions into an opaque `AuthorityState`. `authorityRevisionLeaf` gives exact canonical leaf bytes; the state snapshot exposes the active provider checkpoint key and current authority root/policy but not the retired-key ledger.
- `src/checkpoint.ts` verifies one provider signature and hashes the signed checkpoint **statement**. Its `verifyCheckpointExtension` is same-key only and does not fold mixed leaves, so a key rotation requires historical state replay.
- `src/history-frontier.ts` reconstructs the RFC history root incrementally; `src/history.ts` can derive/verify inclusion and consistency from retained canonical leaves.
- `src/action.ts` verifies an actor signature against a caller-supplied historical authority state. It does not authenticate the action's observed checkpoint, predecessor, operation uniqueness, transaction effect or current app role. `src/completion-receipt.ts` verifies inclusion under a caller-supplied signed head; it does not authenticate that head.
- The proposed observer wire contract is `../1bridge-observer/docs/source-pull-contract.md` in the sibling repo. It requires contiguous leaves and every signed checkpoint from genesis to a fixed target. Source errors or an isolated hidden event without independent evidence are coverage limitations, not cryptographic findings.

## Journey and states

| Step | Caller | State before → after | Failure |
|---|---|---|---|
| Pin | Client/observer | Independently delivered anchor pin + exact signed anchor → verified authority genesis | Provider-substituted pin/anchor rejects |
| Start | Client/observer | Anchor + signed size-zero checkpoint → authenticated genesis | Wrong signer, nonempty root, policy, feed or predecessor rejects |
| Append | Client/observer | Accepted checkpoint plus contiguous canonical mixed leaves → tentative history frontier, authority and per-key action heads | Unknown/reordered/changed leaf, invalid revision/action, stale binding/operation or predecessor rejects |
| Seal | Client/observer | Tentative leaves + next immediate signed checkpoint → accepted prefix | Wrong signer/root/epoch/size/previous or fork rejects |
| Check receipt | Client/observer | Accepted prefix + exact integrated receipt and leaf → historically authenticated inclusion | Missing leaf/checkpoint, divergent receipt head or changed identity rejects |

The output is an authenticated **prefix relative to the customer's independent pin**. It does not establish global freshness, independent custody, product database effect truth, decrypted opening validity, or observer availability.

## Replay contract

Implement one browser-safe `replayGovernanceHistory(signedAnchor, expectedPin, canonicalLeaves, signedCheckpoints)` for a complete retained prefix, including signed genesis. It returns an immutable snapshot with feed ID, accepted size, final checkpoint hash, authority root/revision/policy, and per-actor-key last action hashes. This first API reconstructs from exact bytes and does not accept an unverified serialized state. The caller retains the original bytes; any next bounded page is checked by replaying the retained prefix plus new bytes. That has a measurable cold-start/catch-up cost and must be benchmarked before a high-volume Vercel claim. The observer can persist exact evidence pages but may not mark a prefix accepted on storage presence alone.

The replay loop sorts nothing. It requires a dense ordered checkpoint array beginning at signed size-zero genesis, each next checkpoint with strictly greater size and `previous === checkpointHash(previous.statement)`, and exactly `final.size` dense canonical leaf bytes. For each checkpoint, replay only the next contiguous range of leaves up to its stated size, then compare computed history root, replayed authority root and policy epoch, feed ID and signer key ID. Verify its signature under the currently customer-authorized provider key, which may have changed in that range through a valid root-signed rotation leaf. Derive RFC consistency evidence from the retained leaf prefix; no source-provided proof substitutes for exact leaves. Reject an extra leaf after the final checkpoint and an unsealed tail.

Recognize only exact `authority.revision` and `governance.completion` canonical records. For each revision, compare its re-encoded `authorityRevisionLeaf` to the source bytes, then call `applyAuthorityRevision`. For each completion, compare its re-encoded `governanceCompletionLeaf` to source bytes, verify its actor signature/binding against the state **at that leaf**, and reject duplicate `operationId` even if the signatures differ. Require `observedCheckpointHash` to be an already authenticated checkpoint in the same chain before this leaf; a checkpoint enclosing this leaf cannot be its observed prior view. Do not demand that the observed checkpoint be the immediately preceding physical leaf or checkpoint, since unrelated actions may interleave.

For each actor signing key ID, first completion requires `previousActionHash:null` and `previousReceipt:null`. Every later completion under that same key requires both fields, `previousActionHash` equal to the last accepted action statement hash, and the receipt to identify that last action's exact retained leaf and operation/effect. The receipt checkpoint must be a previously authenticated ancestor of the current leaf's observed checkpoint and the current integrating checkpoint; verify its inclusion proof against its exact retained leaf and historically authorized signed head. This rejects a plausible validly signed receipt from a divergent branch and detects a suppressed predecessor when a later same-key action exposes it. A later action under a different key cannot reveal another key's hidden tail. The library does not infer absence of an unpublished first action or prove that the provider did not show another fork elsewhere.

The API may throw a typed/structured replay error with leaf/checkpoint index and reason for a failed complete prefix; it must not silently skip an item. Keep outputs defensive and bound individual leaf, checkpoint, receipt, and array sizes before expensive crypto. Reject accessor, sparse, prototype-spoofed or noncanonical parsed data. Do not add a generic policy engine, database adapter, runtime crypto dependency, or Node builtins to the browser entry point.

## Changes and proposed names

| Path/name | Responsibility | Name decision |
|---|---|---|
| `src/replay.ts` `replayGovernanceHistory` | Verify one supplied complete signed prefix under a pinned anchor | Keep; `History` indicates whole-prefix work, no freshness claim |
| `src/replay.ts` `GovernanceReplaySnapshot` | Report accepted prefix, authority and actor-key heads | Keep; omit private mutable trusted state |
| `src/index.ts` | Export browser-safe replay entry | Keep package public surface consistent |
| `test/replay.test.ts` | Cross-module history and adversarial fixtures | Lowest layer for cryptographic composition |
| `docs/mixed-history-replay-profile.md` | Accepted claims, limits and performance | Required before observer consumption |

## Test plan

1. Write a valid mixed fixture from real keys and signed artifacts before the export exists; observe the focused missing-export failure. Include genesis, recipient-bound actor keys, policy revision, provider-key rotation, two actors, at least one same-key second action with prior receipt, and nontrivial RFC inclusion.
2. Mutate one invariant at a time: wrong authority root or policy under a valid provider signature; unauthorized old/new provider key; missing immediate checkpoint; reordered/skipped/changed leaf; stale/revoked actor; duplicate operation ID; wrong observed checkpoint (future/divergent); first-action false null predecessor; later-action missing/wrong predecessor; prior receipt for a different leaf/effect/key; historically valid receipt from a divergent branch; sparse/accessor/noncanonical input. Each must fail for the intended reason.
3. Implement the minimum complete-prefix verifier and immutable snapshot. Break one predecessor or signer check deliberately and watch its targeted test fail, then restore.
4. Cross-check reconstructed roots and inclusion/consistency with independent fixture/oracle where possible. Run package tests, typecheck, build, Node/browser import smoke, diff check and independent spec/quality review. Benchmark replay cost at 100, 1,000 and 10,000 leaves in the later observer increment; do not claim Vercel scale until measured.

## Principles, smells and verification

SRP: lifecycle owns root-authorized revisions, action owns one actor signature, receipt owns one inclusion, replay composes the retained chain. DRY: re-use those exact canonical and crypto functions; avoid duplicate parsers. YAGNI: complete-prefix reconstruction now, versioned trusted snapshot only after a benchmark demonstrates need. KISS: one feed and one ordered chain per invocation. Name strain: `replayGovernanceHistory` describes the full supplied prefix but cannot mean global freshness; document that limit in API docs. Boy Scout cleanup stays in touched files and separate from behavior changes. This increment touches no 1Bridge app source; app gates apply only after integration.
