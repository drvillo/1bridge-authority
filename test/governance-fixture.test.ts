import { beforeAll, describe, expect, it } from 'vitest'
import * as api from '../src/index.js'

const FEED = 'a'.repeat(64)
const WORKSPACE = 'b'.repeat(64)
const ALICE = 'c'.repeat(64)
const BOB = 'd'.repeat(64)
const WRONG = '0'.repeat(64)

async function signedRevision(state: api.AuthorityState, operation: api.AuthorityOperation, root: CryptoKeyPair) {
  const current = api.authorityStateSnapshot(state)
  const bindings = current.bindings.filter(value => !('binding' in operation) || value.subjectId !== operation.binding.subjectId)
  if ('binding' in operation) bindings.push(operation.binding)
  const entries = await Promise.all(bindings.map(async value => ({
    key: await api.authorityMapKey(value.subjectId), valueHash: await api.authorityBindingHash(value),
  })))
  entries.sort((a, b) => a.key < b.key ? -1 : a.key > b.key ? 1 : 0)
  return api.signAuthorityRevision({ version: 1, feedId: FEED, workspaceId: WORKSPACE,
    number: current.revision + 1, previous: current.revisionHash, previousRoot: current.authorityRoot,
    expectedPolicyEpoch: current.policyEpoch, operation,
    authorityRoot: 'binding' in operation ? await api.orderedMapRoot(entries) : current.authorityRoot,
    policyEpoch: current.policyEpoch + (operation.kind === 'policy' ? 1 : 0),
    signerKeyId: await api.signingKeyId(root.publicKey) }, root)
}

async function actorBinding(subjectId: string, pair: CryptoKeyPair): Promise<api.ActiveBinding> {
  return { subjectId, keySpki: await api.exportSigningPublicKey(pair.publicKey),
    keyId: await api.signingKeyId(pair.publicKey), version: 1,
    scope: { kind: 'workspace', workspaceId: WORKSPACE }, actionClasses: ['document.read'],
    recipientKeyCommitment: null, status: 'active' }
}

async function head(leaves: Uint8Array[], state: api.AuthorityState, previous: api.SignedCheckpoint | null, signer: CryptoKeyPair) {
  const current = api.authorityStateSnapshot(state)
  return api.signCheckpoint({ version: 1, feedId: FEED, size: leaves.length, historyRoot: await api.merkleRoot(leaves),
    authorityRoot: current.authorityRoot, policyEpoch: current.policyEpoch,
    signerKeyId: await api.signingKeyId(signer.publicKey),
    previous: previous ? await api.checkpointHash(previous.statement) : null }, signer)
}

async function action(state: api.AuthorityState, observed: api.SignedCheckpoint, actor: CryptoKeyPair,
  subjectId: string, operationId: string, previousReceipt: api.CompletionReceipt | null = null) {
  const current = api.authorityStateSnapshot(state)
  const bound = current.bindings.find(value => value.subjectId === subjectId)
  if (!bound) throw new TypeError('Missing fixture actor')
  return api.signGovernanceAction({ version: 1, feedId: FEED, workspaceId: WORKSPACE, operationId,
    actorSubjectId: subjectId, actorKeyId: await api.signingKeyId(actor.publicKey), actorVersion: bound.version,
    scope: { kind: 'workspace', workspaceId: WORKSPACE }, actionClass: 'document.read',
    authorityRevision: current.revision, authorityRevisionHash: current.revisionHash,
    authorityRoot: current.authorityRoot, policyEpoch: current.policyEpoch, observerPolicyHash: current.observerPolicyHash,
    intentCommitment: 'e'.repeat(64), effectCommitment: 'f'.repeat(64),
    observedCheckpointHash: await api.checkpointHash(observed.statement),
    previousActionHash: previousReceipt?.actionHash ?? null, previousReceipt }, actor)
}

async function receipt(signed: api.SignedAction, leaf: Uint8Array, index: number,
  leaves: Uint8Array[], checkpoint: api.SignedCheckpoint): Promise<api.CompletionReceipt> {
  return { version: 1, status: 'integrated', feedId: FEED, operationId: signed.statement.operationId,
    actionHash: await api.governanceActionHash(signed.statement), effectCommitment: signed.statement.effectCommitment,
    leafIndex: index, leafHash: await api.hashLeaf(leaf), checkpoint,
    inclusionProof: await api.inclusionProof(leaves, index) }
}

async function buildFixture() {
  const [root, recovery, provider, rotated, alice, bob, outsider] = await Promise.all([
    api.generateSigningKey(), api.generateSigningKey(), api.generateSigningKey(), api.generateSigningKey(),
    api.generateSigningKey(), api.generateSigningKey(), api.generateSigningKey(),
  ])
  const anchor = await api.createAuthorityAnchor({ feedId: FEED, workspaceId: WORKSPACE,
    rootPublicKey: root.publicKey, recoveryPublicKey: recovery.publicKey, checkpointPublicKey: provider.publicKey })
  const signedAnchor = await api.signAuthorityAnchor(anchor, root, recovery)
  const pin = await api.anchorHash(anchor)
  const initial = await api.verifyAuthorityAnchor(signedAnchor, pin)
  const leaves: Uint8Array[] = []
  const genesis = await head(leaves, initial, null, provider)

  const bindAlice = await signedRevision(initial, { kind: 'bind', binding: await actorBinding(ALICE, alice) }, root)
  const afterAlice = await api.applyAuthorityRevision(initial, bindAlice)
  leaves.push(api.authorityRevisionLeaf(bindAlice))
  const h1 = await head(leaves, afterAlice, genesis, provider)
  const alice1 = await action(afterAlice, h1, alice, ALICE, '1'.repeat(64))
  const aliceLeaf1 = api.governanceCompletionLeaf(alice1)
  leaves.push(aliceLeaf1)
  const h2 = await head(leaves, afterAlice, h1, provider)
  const aliceReceipt1 = await receipt(alice1, aliceLeaf1, 1, leaves, h2)

  const bindBob = await signedRevision(afterAlice, { kind: 'bind', binding: await actorBinding(BOB, bob) }, root)
  const afterBob = await api.applyAuthorityRevision(afterAlice, bindBob)
  leaves.push(api.authorityRevisionLeaf(bindBob))
  const h3 = await head(leaves, afterBob, h2, provider)
  const bob1 = await action(afterBob, h3, bob, BOB, '2'.repeat(64))
  const bobLeaf1 = api.governanceCompletionLeaf(bob1)
  leaves.push(bobLeaf1)
  const h4 = await head(leaves, afterBob, h3, provider)
  const bobReceipt1 = await receipt(bob1, bobLeaf1, 3, leaves, h4)

  const policyBody = { strictAudit: true }
  const policy = await signedRevision(afterBob, { kind: 'policy', body: policyBody,
    policyHash: await api.observerPolicyHash(policyBody) }, root)
  const afterPolicy = await api.applyAuthorityRevision(afterBob, policy)
  leaves.push(api.authorityRevisionLeaf(policy))
  const h5 = await head(leaves, afterPolicy, h4, provider)
  const rotation = await signedRevision(afterPolicy, { kind: 'rotate-checkpoint',
    checkpointKeySpki: await api.exportSigningPublicKey(rotated.publicKey),
    checkpointKeyId: await api.signingKeyId(rotated.publicKey) }, root)
  const afterRotation = await api.applyAuthorityRevision(afterPolicy, rotation)
  leaves.push(api.authorityRevisionLeaf(rotation))
  const h6 = await head(leaves, afterRotation, h5, rotated)

  const alice2 = await action(afterRotation, h6, alice, ALICE, '3'.repeat(64), aliceReceipt1)
  const aliceLeaf2 = api.governanceCompletionLeaf(alice2)
  leaves.push(aliceLeaf2)
  const h7 = await head(leaves, afterRotation, h6, rotated)
  const aliceReceipt2 = await receipt(alice2, aliceLeaf2, 6, leaves, h7)
  const revokeAlice = await signedRevision(afterRotation, { kind: 'revoke', binding: {
    subjectId: ALICE, keyId: await api.signingKeyId(alice.publicKey), version: 2, status: 'revoked' } }, root)
  const afterRevoke = await api.applyAuthorityRevision(afterRotation, revokeAlice)
  leaves.push(api.authorityRevisionLeaf(revokeAlice))
  const h8 = await head(leaves, afterRevoke, h7, rotated)

  // This sibling revision is root-signed and creates a different valid branch after h2.
  const siblingBody = { branch: true }
  const sibling = await signedRevision(afterAlice, { kind: 'policy', body: siblingBody,
    policyHash: await api.observerPolicyHash(siblingBody) }, root)
  const siblingState = await api.applyAuthorityRevision(afterAlice, sibling)
  const siblingLeaves = [leaves[0]!, leaves[1]!, api.authorityRevisionLeaf(sibling)]
  const siblingHead = await head(siblingLeaves, siblingState, h2, provider)
  const siblingReceipt = await receipt(alice1, aliceLeaf1, 1, siblingLeaves, siblingHead)
  return { signedAnchor, pin, leaves, siblingLeaves,
    states: { initial, afterAlice, afterBob, afterPolicy, afterRotation, afterRevoke, siblingState },
    revisions: { bindAlice, bindBob, policy, rotation, revokeAlice, sibling },
    heads: { genesis, h1, h2, h3, h4, h5, h6, h7, h8, siblingHead },
    actions: { alice1, bob1, alice2 }, receipts: { aliceReceipt1, bobReceipt1, aliceReceipt2, siblingReceipt },
    keys: { provider, rotated, alice, bob, outsider }, aliceLeaf1, bobLeaf1, aliceLeaf2 }
}

let fixture: Awaited<ReturnType<typeof buildFixture>>
beforeAll(async () => { fixture = await buildFixture() })

describe('mixed governance history fixture', () => {
  it('checks historical actors and exact receipt inclusion across policy and provider rotation', async () => {
    const { states, actions, receipts, heads, leaves, keys } = fixture
    expect(await api.verifyGovernanceAction(actions.alice1, states.afterAlice)).toBe(true)
    expect(await api.verifyGovernanceAction(actions.bob1, states.afterBob)).toBe(true)
    expect(await api.verifyGovernanceAction(actions.alice2, states.afterRotation)).toBe(true)
    expect(await api.verifyReceiptInclusion(receipts.aliceReceipt1, fixture.aliceLeaf1, heads.h2)).toBe(true)
    expect(await api.verifyReceiptInclusion(receipts.bobReceipt1, fixture.bobLeaf1, heads.h4)).toBe(true)
    expect(await api.verifyReceiptInclusion(receipts.aliceReceipt2, fixture.aliceLeaf2, heads.h7)).toBe(true)
    expect(await api.verifyCheckpoint(heads.h5, keys.provider.publicKey)).toBe(true)
    expect(await api.verifyCheckpoint(heads.h6, keys.rotated.publicKey)).toBe(true)
    expect(heads.h6.statement.previous).toBe(await api.checkpointHash(heads.h5.statement))
    expect(await api.verifyConsistency(5, 6, heads.h5.statement.historyRoot,
      heads.h6.statement.historyRoot, await api.consistencyProof(leaves.slice(0, 6), 5))).toBe(true)
    expect(receipts.aliceReceipt1.actionHash).toBe(actions.alice2.statement.previousActionHash)
  })

  it('rejects stale and revoked actors and skipped authority revisions at current API boundaries', async () => {
    const { states, actions, heads, receipts, keys, revisions, signedAnchor, pin } = fixture
    expect(await api.verifyGovernanceAction(actions.alice1, states.afterBob)).toBe(false)
    expect(await api.verifyGovernanceAction(actions.alice2, states.afterRevoke)).toBe(false)
    const revokedAttempt = await action(states.afterRevoke, heads.h8, keys.alice, ALICE, '4'.repeat(64), receipts.aliceReceipt2)
    expect(await api.verifyGovernanceAction(revokedAttempt, states.afterRevoke)).toBe(false)
    await expect(api.applyAuthorityRevision(states.initial, revisions.bindBob)).rejects.toThrow()
    await expect(api.replayAuthorityRevisions(signedAnchor, pin, [revisions.bindBob, revisions.bindAlice])).rejects.toThrow()
  })

  it('shows that valid signatures and inclusion alone accept wrong authority root, policy or signer', async () => {
    const { states, heads, keys, receipts, aliceLeaf2 } = fixture
    const expected = api.authorityStateSnapshot(states.afterRotation)
    const wrongRoot = await api.signCheckpoint({ ...heads.h7.statement, authorityRoot: WRONG }, keys.rotated)
    const wrongPolicy = await api.signCheckpoint({ ...heads.h7.statement, policyEpoch: expected.policyEpoch + 1 }, keys.rotated)
    const wrongSigner = await api.signCheckpoint({ ...heads.h7.statement,
      signerKeyId: await api.signingKeyId(keys.outsider.publicKey) }, keys.outsider)
    for (const candidate of [wrongRoot, wrongPolicy, wrongSigner]) {
      expect(await api.verifyReceiptInclusion({ ...receipts.aliceReceipt2, checkpoint: candidate }, aliceLeaf2, candidate)).toBe(true)
    }
    expect(await api.verifyCheckpoint(wrongRoot, keys.rotated.publicKey)).toBe(true)
    expect(await api.verifyCheckpoint(wrongPolicy, keys.rotated.publicKey)).toBe(true)
    expect(wrongRoot.statement.authorityRoot).not.toBe(expected.authorityRoot)
    expect(wrongPolicy.statement.policyEpoch).not.toBe(expected.policyEpoch)
    expect(await api.verifyCheckpoint(wrongSigner, keys.rotated.publicKey)).toBe(false)
    expect(wrongSigner.statement.signerKeyId).not.toBe(expected.checkpointKeyId)
  })

  it('detects reordered leaves and bad same-key checkpoint predecessor or consistency', async () => {
    const { leaves, heads, keys, aliceLeaf2, receipts } = fixture
    const reordered = [...leaves.slice(0, 7)]
    ;[reordered[1], reordered[2]] = [reordered[2]!, reordered[1]!]
    expect(await api.verifyInclusion(aliceLeaf2, 6, 7, receipts.aliceReceipt2.inclusionProof,
      await api.merkleRoot(reordered))).toBe(false)
    const proof = await api.consistencyProof(leaves.slice(0, 7), 6)
    expect(await api.verifyCheckpointExtension(heads.h6, heads.h7, proof, keys.rotated.publicKey)).toBe(true)
    const badPrevious = await api.signCheckpoint({ ...heads.h7.statement, previous: WRONG }, keys.rotated)
    expect(await api.verifyCheckpoint(badPrevious, keys.rotated.publicKey)).toBe(true)
    expect(await api.verifyCheckpointExtension(heads.h6, badPrevious, proof, keys.rotated.publicKey)).toBe(false)
    expect(await api.verifyCheckpointExtension(heads.h6, heads.h7, [WRONG], keys.rotated.publicKey)).toBe(false)
  })

  it('exposes a divergent prior receipt and absent actor-stream link as pending replay checks', async () => {
    const { states, heads, keys, receipts, actions, aliceLeaf1, leaves, siblingLeaves } = fixture
    expect(await api.verifyReceiptInclusion(receipts.siblingReceipt, aliceLeaf1, heads.siblingHead)).toBe(true)
    expect(await api.verifyCheckpoint(heads.siblingHead, keys.provider.publicKey)).toBe(true)
    expect(heads.siblingHead.statement.previous).toBe(heads.h3.statement.previous)
    expect(heads.siblingHead.statement.historyRoot).not.toBe(heads.h3.statement.historyRoot)
    expect(await api.verifyConsistency(3, 6, heads.siblingHead.statement.historyRoot,
      heads.h6.statement.historyRoot, await api.consistencyProof(leaves.slice(0, 6), 3))).toBe(false)
    const divergent = await action(states.afterRotation, heads.h6, keys.alice, ALICE, '5'.repeat(64), receipts.siblingReceipt)
    expect(await api.verifyGovernanceAction(divergent, states.afterRotation)).toBe(true)
    expect(divergent.statement.previousReceipt?.checkpoint.statement.historyRoot).toBe(await api.merkleRoot(siblingLeaves))
    const missing = await action(states.afterRotation, heads.h6, keys.alice, ALICE, '6'.repeat(64))
    expect(await api.verifyGovernanceAction(missing, states.afterRotation)).toBe(true)
    expect(missing.statement.previousActionHash).toBeNull()
    expect(actions.alice2.statement.previousActionHash).toBe(receipts.aliceReceipt1.actionHash)
    await expect(api.signGovernanceAction({ ...missing.statement,
      previousActionHash: receipts.aliceReceipt1.actionHash }, keys.alice)).rejects.toThrow()
  })

  it('replays the mixed main chain from the independent pin', async () => {
    const { signedAnchor, pin, leaves, heads, states, actions, keys } = fixture
    const checkpoints = [heads.genesis, heads.h1, heads.h2, heads.h3, heads.h4,
      heads.h5, heads.h6, heads.h7, heads.h8]
    const replayed = await api.replayGovernanceHistory(signedAnchor, pin, leaves, checkpoints)
    const final = api.authorityStateSnapshot(states.afterRevoke)
    expect(replayed).toMatchObject({
      feedId: FEED, size: leaves.length, checkpointHash: await api.checkpointHash(heads.h8.statement),
      authorityRoot: final.authorityRoot, authorityRevision: final.revision,
      authorityRevisionHash: final.revisionHash, policyEpoch: final.policyEpoch,
      observerPolicyHash: final.observerPolicyHash,
    })
    expect(replayed.actorHeads).toEqual([
      { actorKeyId: await api.signingKeyId(keys.alice.publicKey),
        actionHash: await api.governanceActionHash(actions.alice2.statement) },
      { actorKeyId: await api.signingKeyId(keys.bob.publicKey),
        actionHash: await api.governanceActionHash(actions.bob1.statement) },
    ].sort((a, b) => a.actorKeyId.localeCompare(b.actorKeyId)))
  })
})
