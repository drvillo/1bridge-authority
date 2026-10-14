import { beforeAll, describe, expect, it } from 'vitest'
import * as authority from '../src/index.js'

const FEED = 'a'.repeat(64)
const WORKSPACE = 'b'.repeat(64)
const ALICE = 'c'.repeat(64)
const BOB = 'd'.repeat(64)
const WRONG = '0'.repeat(64)

async function revision(state: authority.AuthorityState, operation: authority.AuthorityOperation, root: CryptoKeyPair) {
  const current = authority.authorityStateSnapshot(state)
  const bindings = current.bindings.filter(item => !('binding' in operation) || item.subjectId !== operation.binding.subjectId)
  if ('binding' in operation) bindings.push(operation.binding)
  const entries = await Promise.all(bindings.map(async item => ({
    key: await authority.authorityMapKey(item.subjectId), valueHash: await authority.authorityBindingHash(item),
  })))
  entries.sort((a, b) => a.key < b.key ? -1 : a.key > b.key ? 1 : 0)
  return authority.signAuthorityRevision({ version: 1, feedId: FEED, workspaceId: WORKSPACE,
    number: current.revision + 1, previous: current.revisionHash, previousRoot: current.authorityRoot,
    expectedPolicyEpoch: current.policyEpoch, operation,
    authorityRoot: 'binding' in operation ? await authority.orderedMapRoot(entries) : current.authorityRoot,
    policyEpoch: current.policyEpoch + (operation.kind === 'policy' ? 1 : 0),
    signerKeyId: await authority.signingKeyId(root.publicKey) }, root)
}

async function binding(subjectId: string, pair: CryptoKeyPair): Promise<authority.ActiveBinding> {
  return { subjectId, keySpki: await authority.exportSigningPublicKey(pair.publicKey),
    keyId: await authority.signingKeyId(pair.publicKey), version: 1,
    scope: { kind: 'workspace', workspaceId: WORKSPACE }, actionClasses: ['document.read'],
    recipientKeyCommitment: null, status: 'active' }
}

async function checkpoint(leaves: Uint8Array[], state: authority.AuthorityState,
  previous: authority.SignedCheckpoint | null, signer: CryptoKeyPair) {
  const current = authority.authorityStateSnapshot(state)
  return authority.signCheckpoint({ version: 1, feedId: FEED, size: leaves.length,
    historyRoot: await authority.merkleRoot(leaves), authorityRoot: current.authorityRoot,
    policyEpoch: current.policyEpoch, signerKeyId: await authority.signingKeyId(signer.publicKey),
    previous: previous ? await authority.checkpointHash(previous.statement) : null }, signer)
}

async function action(state: authority.AuthorityState, observed: authority.SignedCheckpoint,
  signer: CryptoKeyPair, subjectId: string, operationId: string, previousReceipt: authority.CompletionReceipt | null = null) {
  const current = authority.authorityStateSnapshot(state)
  const actor = current.bindings.find(item => item.subjectId === subjectId)
  if (!actor) throw new TypeError('Missing fixture actor')
  return authority.signGovernanceAction({ version: 1, feedId: FEED, workspaceId: WORKSPACE, operationId,
    actorSubjectId: subjectId, actorKeyId: await authority.signingKeyId(signer.publicKey), actorVersion: actor.version,
    scope: { kind: 'workspace', workspaceId: WORKSPACE }, actionClass: 'document.read',
    authorityRevision: current.revision, authorityRevisionHash: current.revisionHash,
    authorityRoot: current.authorityRoot, policyEpoch: current.policyEpoch, observerPolicyHash: current.observerPolicyHash,
    intentCommitment: 'e'.repeat(64), effectCommitment: 'f'.repeat(64),
    observedCheckpointHash: await authority.checkpointHash(observed.statement),
    previousActionHash: previousReceipt?.actionHash ?? null, previousReceipt }, signer)
}

async function receipt(signed: authority.SignedAction, leaf: Uint8Array, index: number,
  leaves: Uint8Array[], head: authority.SignedCheckpoint): Promise<authority.CompletionReceipt> {
  return { version: 1, status: 'integrated', feedId: FEED, operationId: signed.statement.operationId,
    actionHash: await authority.governanceActionHash(signed.statement),
    effectCommitment: signed.statement.effectCommitment, leafIndex: index,
    leafHash: await authority.hashLeaf(leaf), checkpoint: head,
    inclusionProof: await authority.inclusionProof(leaves, index) }
}

async function fixture() {
  const [root, recovery, provider, rotated, alice, bob, outsider] = await Promise.all([
    authority.generateSigningKey(), authority.generateSigningKey(), authority.generateSigningKey(),
    authority.generateSigningKey(), authority.generateSigningKey(), authority.generateSigningKey(),
    authority.generateSigningKey(),
  ])
  const anchor = await authority.createAuthorityAnchor({ feedId: FEED, workspaceId: WORKSPACE,
    rootPublicKey: root.publicKey, recoveryPublicKey: recovery.publicKey, checkpointPublicKey: provider.publicKey })
  const signedAnchor = await authority.signAuthorityAnchor(anchor, root, recovery)
  const pin = await authority.anchorHash(anchor)
  let state = await authority.verifyAuthorityAnchor(signedAnchor, pin)
  const leaves: Uint8Array[] = []
  const heads: authority.SignedCheckpoint[] = [await checkpoint(leaves, state, null, provider)]
  async function seal(signer: CryptoKeyPair) { heads.push(await checkpoint(leaves, state, heads.at(-1)!, signer)) }
  async function appendRevision(operation: authority.AuthorityOperation, signer: CryptoKeyPair) {
    const signed = await revision(state, operation, root)
    state = await authority.applyAuthorityRevision(state, signed)
    leaves.push(authority.authorityRevisionLeaf(signed))
    await seal(signer)
    return signed
  }
  async function appendAction(actor: CryptoKeyPair, subject: string, operation: string,
    previous: authority.CompletionReceipt | null, signer: CryptoKeyPair) {
    const signed = await action(state, heads.at(-1)!, actor, subject, operation, previous)
    const index = leaves.length
    const leaf = authority.governanceCompletionLeaf(signed)
    leaves.push(leaf)
    await seal(signer)
    return { signed, leaf, integrated: await receipt(signed, leaf, index, leaves, heads.at(-1)!) }
  }
  await appendRevision({ kind: 'bind', binding: await binding(ALICE, alice) }, provider)
  const first = await appendAction(alice, ALICE, '1'.repeat(64), null, provider)
  const afterFirst = state
  await appendRevision({ kind: 'bind', binding: await binding(BOB, bob) }, provider)
  const other = await appendAction(bob, BOB, '2'.repeat(64), null, provider)
  const body = { strictAudit: true }
  await appendRevision({ kind: 'policy', body, policyHash: await authority.observerPolicyHash(body) }, provider)
  await appendRevision({ kind: 'rotate-checkpoint', checkpointKeySpki: await authority.exportSigningPublicKey(rotated.publicKey),
    checkpointKeyId: await authority.signingKeyId(rotated.publicKey) }, rotated)
  const second = await appendAction(alice, ALICE, '3'.repeat(64), first.integrated, rotated)
  return { signedAnchor, pin, leaves, heads, first, other, second, afterFirst,
    keys: { root, provider, rotated, alice, bob, outsider }, state }
}

let history: Awaited<ReturnType<typeof fixture>>
beforeAll(async () => { history = await fixture() })

describe('pinned mixed-history replay', () => {
  it('requires the independent anchor pin and an authorized signed genesis', async () => {
    await expect(authority.replayGovernanceHistory(history.signedAnchor, WRONG, [],
      [history.heads[0]!])).rejects.toThrow(/pin mismatch/)
    const genesis = history.heads[0]!
    const wrongSigner = await authority.signCheckpoint({ ...genesis.statement,
      signerKeyId: await authority.signingKeyId(history.keys.outsider.publicKey) }, history.keys.outsider)
    await expect(authority.replayGovernanceHistory(history.signedAnchor, history.pin, [],
      [wrongSigner])).rejects.toThrow(/genesis/)
    const wrongRoot = await authority.signCheckpoint({ ...genesis.statement,
      authorityRoot: WRONG }, history.keys.provider)
    await expect(authority.replayGovernanceHistory(history.signedAnchor, history.pin, [],
      [wrongRoot])).rejects.toThrow(/genesis/)
  })

  it('accepts an authenticated empty prefix and exposes no actor head', async () => {
    const result = await authority.replayGovernanceHistory(history.signedAnchor, history.pin, [], [history.heads[0]!])
    expect(result.size).toBe(0)
    expect(result.authorityRevision).toBe(0)
    expect(result.actorHeads).toEqual([])
    expect(Object.isFrozen(result)).toBe(true)
    expect(Object.isFrozen(result.actorHeads)).toBe(true)
  })

  it('accepts a complete mixed prefix across two actors and provider rotation', async () => {
    const result = await authority.replayGovernanceHistory(history.signedAnchor, history.pin, history.leaves, history.heads)
    expect(result.feedId).toBe(FEED)
    expect(result.size).toBe(7)
    expect(result.checkpointHash).toBe(await authority.checkpointHash(history.heads.at(-1)!.statement))
    expect(result.authorityRoot).toBe(authority.authorityStateSnapshot(history.state).authorityRoot)
    expect(result.policyEpoch).toBe(1)
    expect(result.actorHeads).toEqual([
      { actorKeyId: await authority.signingKeyId(history.keys.alice.publicKey), actionHash: await authority.governanceActionHash(history.second.signed.statement) },
      { actorKeyId: await authority.signingKeyId(history.keys.bob.publicKey), actionHash: await authority.governanceActionHash(history.other.signed.statement) },
    ].sort((a, b) => a.actorKeyId.localeCompare(b.actorKeyId)))
  })

  it('rejects a valid provider signature over the wrong authority root or policy epoch', async () => {
    const final = history.heads.at(-1)!
    for (const changed of [
      { ...final.statement, authorityRoot: WRONG },
      { ...final.statement, policyEpoch: final.statement.policyEpoch + 1 },
    ]) {
      const signed = await authority.signCheckpoint(changed, history.keys.rotated)
      await expect(authority.replayGovernanceHistory(history.signedAnchor, history.pin, history.leaves,
        [...history.heads.slice(0, -1), signed])).rejects.toThrow(/disagrees/)
    }
  })

  it('rejects a signer not authorized at that historical checkpoint', async () => {
    const beforeRotation = history.heads[5]!
    const outsider = await authority.signCheckpoint({ ...beforeRotation.statement,
      signerKeyId: await authority.signingKeyId(history.keys.outsider.publicKey) }, history.keys.outsider)
    await expect(authority.replayGovernanceHistory(history.signedAnchor, history.pin, history.leaves,
      [...history.heads.slice(0, 5), outsider, ...history.heads.slice(6)])).rejects.toThrow(/disagrees/)
    const rotationHead = history.heads[6]!
    const stale = await authority.signCheckpoint({ ...rotationHead.statement,
      signerKeyId: await authority.signingKeyId(history.keys.provider.publicKey) }, history.keys.provider)
    await expect(authority.replayGovernanceHistory(history.signedAnchor, history.pin, history.leaves,
      [...history.heads.slice(0, 6), stale, history.heads[7]!])).rejects.toThrow(/disagrees/)
  })

  it('rejects missing, forked, reordered and unsealed history', async () => {
    const run = (leaves: Uint8Array[], heads: authority.SignedCheckpoint[]) =>
      authority.replayGovernanceHistory(history.signedAnchor, history.pin, leaves, heads)
    await expect(run(history.leaves, [history.heads[0]!, ...history.heads.slice(2)])).rejects.toThrow(/forks/)
    const reordered = [...history.leaves]
    ;[reordered[1], reordered[2]] = [reordered[2]!, reordered[1]!]
    await expect(run(reordered, history.heads)).rejects.toThrow()
    await expect(run([...history.leaves, history.leaves[1]!], history.heads)).rejects.toThrow(/Unsealed/)
    const fork = await authority.signCheckpoint({ ...history.heads[7]!.statement, previous: WRONG }, history.keys.rotated)
    await expect(run(history.leaves, [...history.heads.slice(0, 7), fork])).rejects.toThrow(/forks/)
  })

  it('rejects a second same-key action that suppresses its predecessor', async () => {
    const signed = await action(history.state, history.heads.at(-1)!, history.keys.alice, ALICE, '4'.repeat(64))
    const leaves = [...history.leaves, authority.governanceCompletionLeaf(signed)]
    const head = await checkpoint(leaves, history.state, history.heads.at(-1)!, history.keys.rotated)
    await expect(authority.replayGovernanceHistory(history.signedAnchor, history.pin, leaves,
      [...history.heads, head])).rejects.toThrow(/predecessor mismatch/)
  })

  it('rejects an otherwise valid receipt from a signed divergent branch', async () => {
    const siblingBody = { branch: true }
    const branch = await revision(history.afterFirst, { kind: 'policy', body: siblingBody,
      policyHash: await authority.observerPolicyHash(siblingBody) }, history.keys.root)
    const branchState = await authority.applyAuthorityRevision(history.afterFirst, branch)
    const branchLeaves = [...history.leaves.slice(0, 2), authority.authorityRevisionLeaf(branch)]
    const branchHead = await checkpoint(branchLeaves, branchState, history.heads[2]!, history.keys.provider)
    const branchReceipt = await receipt(history.first.signed, history.first.leaf, 1, branchLeaves, branchHead)
    expect(await authority.verifyReceiptInclusion(branchReceipt, history.first.leaf, branchHead)).toBe(true)
    const signed = await action(history.state, history.heads.at(-1)!, history.keys.alice, ALICE,
      '5'.repeat(64), branchReceipt)
    const leaves = [...history.leaves, authority.governanceCompletionLeaf(signed)]
    const head = await checkpoint(leaves, history.state, history.heads.at(-1)!, history.keys.rotated)
    await expect(authority.replayGovernanceHistory(history.signedAnchor, history.pin, leaves,
      [...history.heads, head])).rejects.toThrow(/predecessor mismatch/)
  })

  it('rejects duplicate operations and receipts that do not identify the exact prior action', async () => {
    const duplicate = await action(history.state, history.heads.at(-1)!, history.keys.alice, ALICE,
      history.first.signed.statement.operationId, history.second.integrated)
    const wrongReceipt = { ...history.second.integrated, operationId: WRONG }
    const wrong = await action(history.state, history.heads.at(-1)!, history.keys.alice, ALICE,
      '6'.repeat(64), wrongReceipt)
    for (const [signed, message] of [[duplicate, /Duplicate operation/], [wrong, /receipt mismatch/]] as const) {
      const leaves = [...history.leaves, authority.governanceCompletionLeaf(signed)]
      const head = await checkpoint(leaves, history.state, history.heads.at(-1)!, history.keys.rotated)
      await expect(authority.replayGovernanceHistory(history.signedAnchor, history.pin, leaves,
        [...history.heads, head])).rejects.toThrow(message)
    }
  })

  it('rejects a first action that falsely names a prior action', async () => {
    const forged = await authority.signGovernanceAction({ ...history.other.signed.statement,
      previousActionHash: history.first.integrated.actionHash,
      previousReceipt: history.first.integrated }, history.keys.bob)
    const leaves = [...history.leaves]
    leaves[3] = authority.governanceCompletionLeaf(forged)
    await expect(authority.replayGovernanceHistory(history.signedAnchor, history.pin, leaves,
      history.heads)).rejects.toThrow(/First action/)
  })

  it('requires the prior receipt head to precede the actor-observed checkpoint', async () => {
    const signed = await authority.signGovernanceAction({ ...history.second.signed.statement,
      operationId: '9'.repeat(64), observedCheckpointHash: await authority.checkpointHash(history.heads[1]!.statement),
      previousActionHash: history.second.integrated.actionHash,
      previousReceipt: history.second.integrated }, history.keys.alice)
    const leaves = [...history.leaves, authority.governanceCompletionLeaf(signed)]
    const head = await checkpoint(leaves, history.state, history.heads.at(-1)!, history.keys.rotated)
    await expect(authority.replayGovernanceHistory(history.signedAnchor, history.pin, leaves,
      [...history.heads, head])).rejects.toThrow(/receipt mismatch/)
  })

  it('rejects a receipt whose leaf, effect or actor stream differs from the predecessor', async () => {
    const altered = [
      { ...history.second.integrated, leafIndex: 0 },
      { ...history.second.integrated, effectCommitment: WRONG },
      { ...history.second.integrated, leafHash: WRONG },
      history.other.integrated,
    ]
    for (const [index, prior] of altered.entries()) {
      const signed = await action(history.state, history.heads.at(-1)!, history.keys.alice, ALICE,
        String(index + 4).repeat(64), prior)
      const leaves = [...history.leaves, authority.governanceCompletionLeaf(signed)]
      const head = await checkpoint(leaves, history.state, history.heads.at(-1)!, history.keys.rotated)
      await expect(authority.replayGovernanceHistory(history.signedAnchor, history.pin, leaves,
        [...history.heads, head])).rejects.toThrow(/predecessor mismatch|receipt mismatch/)
    }
  })

  it('rejects a revoked actor and a future observed checkpoint', async () => {
    const revoked = await revision(history.state, { kind: 'revoke', binding: {
      subjectId: ALICE, keyId: await authority.signingKeyId(history.keys.alice.publicKey),
      version: 2, status: 'revoked' } }, history.keys.root)
    const revokedState = await authority.applyAuthorityRevision(history.state, revoked)
    const leaves = [...history.leaves, authority.authorityRevisionLeaf(revoked)]
    const sealed = await checkpoint(leaves, revokedState, history.heads.at(-1)!, history.keys.rotated)
    const attempt = await action(revokedState, sealed, history.keys.alice, ALICE,
      '7'.repeat(64), history.second.integrated)
    const after = [...leaves, authority.governanceCompletionLeaf(attempt)]
    const head = await checkpoint(after, revokedState, sealed, history.keys.rotated)
    await expect(authority.replayGovernanceHistory(history.signedAnchor, history.pin, after,
      [...history.heads, sealed, head])).rejects.toThrow(/Unauthorized action/)

    const future = await authority.signGovernanceAction({ ...history.second.signed.statement,
      operationId: '8'.repeat(64), observedCheckpointHash: WRONG }, history.keys.alice)
    const futureLeaves = [...history.leaves, authority.governanceCompletionLeaf(future)]
    const futureHead = await checkpoint(futureLeaves, history.state, history.heads.at(-1)!, history.keys.rotated)
    await expect(authority.replayGovernanceHistory(history.signedAnchor, history.pin, futureLeaves,
      [...history.heads, futureHead])).rejects.toThrow(/unauthenticated checkpoint/)
  })

  it('rejects sparse, accessor and noncanonical source input', async () => {
    const sparse = [...history.leaves]
    delete sparse[2]
    await expect(authority.replayGovernanceHistory(history.signedAnchor, history.pin, sparse,
      history.heads)).rejects.toThrow(/dense leaf/)
    const accessor = [...history.heads]
    Object.defineProperty(accessor, '1', { enumerable: true, get: () => history.heads[1] })
    await expect(authority.replayGovernanceHistory(history.signedAnchor, history.pin, history.leaves,
      accessor)).rejects.toThrow(/checkpoint data entry/)
    const text = new TextDecoder().decode(history.leaves[1]!)
    const noncanonical = [...history.leaves]
    noncanonical[1] = new TextEncoder().encode(` ${text}`)
    await expect(authority.replayGovernanceHistory(history.signedAnchor, history.pin, noncanonical,
      history.heads)).rejects.toThrow(/canonical/)
    const malicious = { ...history.signedAnchor,
      get rootSignature(): string { throw new Error('Accessors must never execute') } }
    await expect(authority.replayGovernanceHistory(malicious, history.pin, history.leaves,
      history.heads)).rejects.toThrow(/data properties/)
  })
})
