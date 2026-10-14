import { beforeAll, describe, expect, it } from 'vitest'
import * as authority from '../src/index.js'

const FEED = 'a'.repeat(64)
const WORKSPACE = 'b'.repeat(64)
const ALICE = 'c'.repeat(64)
const BOB = 'd'.repeat(64)
const WRONG = '0'.repeat(64)
const recipientClaim: authority.RecipientKeyClaim = {
  version: 1, workspaceId: WORKSPACE, membershipId: ALICE, membershipKeyRowId: BOB,
  membershipKeyVersion: 7, keySuite: 'x25519',
  keyId: 'riFsLvUkejeCwTXvonmj5M3GEJQnD10r5YxiBLemEsk',
  publicKey: 'v3.x25519.AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA',
}

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

async function binding(subjectId: string, pair: CryptoKeyPair,
  recipientKeyCommitment: authority.Hash | null = null): Promise<authority.ActiveBinding> {
  return { subjectId, keySpki: await authority.exportSigningPublicKey(pair.publicKey),
    keyId: await authority.signingKeyId(pair.publicKey), version: 1,
    scope: { kind: 'workspace', workspaceId: WORKSPACE }, actionClasses: ['document.read'],
    recipientKeyCommitment, status: 'active' }
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
  await appendRevision({ kind: 'bind', binding: await binding(ALICE, alice,
    await authority.recipientKeyClaimHash(recipientClaim)) }, provider)
  const first = await appendAction(alice, ALICE, '1'.repeat(64), null, provider)
  await appendRevision({ kind: 'bind', binding: await binding(BOB, bob) }, provider)
  const other = await appendAction(bob, BOB, '2'.repeat(64), null, provider)
  const body = { strictAudit: true }
  await appendRevision({ kind: 'policy', body, policyHash: await authority.observerPolicyHash(body) }, provider)
  await appendRevision({ kind: 'rotate-checkpoint', checkpointKeySpki: await authority.exportSigningPublicKey(rotated.publicKey),
    checkpointKeyId: await authority.signingKeyId(rotated.publicKey) }, rotated)
  const second = await appendAction(alice, ALICE, '3'.repeat(64), first.integrated, rotated)
  return { signedAnchor, pin, leaves, heads, first, other, second,
    keys: { root, provider, rotated, alice, bob, outsider }, state }
}

let history: Awaited<ReturnType<typeof fixture>>
beforeAll(async () => { history = await fixture() })

describe('pinned mixed-history replay', () => {
  it('propagates a root-signed non-null recipient-key commitment through replay', async () => {
    const expected = await authority.recipientKeyClaimHash(recipientClaim)
    const parsed = authority.parseCanonical(history.leaves[0]!) as unknown as { revision: authority.SignedAuthorityRevision }
    if (parsed.revision.statement.operation.kind !== 'bind') throw new TypeError('Expected Alice binding')
    expect(parsed.revision.statement.operation.binding.recipientKeyCommitment).toBe(expected)
    const genesisState = await authority.verifyAuthorityAnchor(history.signedAnchor, history.pin)
    const afterBinding = await authority.applyAuthorityRevision(genesisState, parsed.revision)
    expect(authority.authorityStateSnapshot(afterBinding).bindings[0]).toMatchObject({ recipientKeyCommitment: expected })
    const replayed = await authority.replayGovernanceHistory(history.signedAnchor, history.pin,
      history.leaves, history.heads)
    expect(replayed.authorityRoot).toBe(authority.authorityStateSnapshot(history.state).authorityRoot)
  })

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
    const branch = await revision(history.state, { kind: 'policy', body: siblingBody,
      policyHash: await authority.observerPolicyHash(siblingBody) }, history.keys.root)
    const branchState = await authority.applyAuthorityRevision(history.state, branch)
    const branchLeaves = [...history.leaves, authority.authorityRevisionLeaf(branch)]
    const branchHead = await checkpoint(branchLeaves, branchState, history.heads[7]!, history.keys.rotated)
    const branchReceipt = await receipt(history.second.signed, history.second.leaf, 6, branchLeaves, branchHead)
    expect(await authority.verifyCheckpoint(branchHead, history.keys.rotated.publicKey)).toBe(true)
    expect(await authority.verifyReceiptInclusion(branchReceipt, history.second.leaf, branchHead)).toBe(true)
    expect(branchReceipt.actionHash).toBe(history.second.integrated.actionHash)
    expect(branchHead.statement.previous).toBe(await authority.checkpointHash(history.heads[7]!.statement))
    expect(branchHead.statement.size).toBe(8)
    const replayedBranch = await authority.replayGovernanceHistory(history.signedAnchor, history.pin,
      branchLeaves, [...history.heads, branchHead])
    expect(replayedBranch.size).toBe(8)
    expect(replayedBranch.checkpointHash).toBe(await authority.checkpointHash(branchHead.statement))

    const canonicalBody = { branch: false }
    const canonicalRevision = await revision(history.state, { kind: 'policy', body: canonicalBody,
      policyHash: await authority.observerPolicyHash(canonicalBody) }, history.keys.root)
    const canonicalState = await authority.applyAuthorityRevision(history.state, canonicalRevision)
    const canonicalLeaves = [...history.leaves, authority.authorityRevisionLeaf(canonicalRevision)]
    const observed = await checkpoint(canonicalLeaves, canonicalState, history.heads[7]!, history.keys.rotated)
    expect(branchHead.statement.size).toBeLessThanOrEqual(observed.statement.size)
    expect(await authority.checkpointHash(branchHead.statement)).not.toBe(await authority.checkpointHash(observed.statement))
    const replayedCanonical = await authority.replayGovernanceHistory(history.signedAnchor, history.pin,
      canonicalLeaves, [...history.heads, observed])
    expect(replayedCanonical.size).toBe(8)
    const signed = await action(canonicalState, observed, history.keys.alice, ALICE,
      '5'.repeat(64), branchReceipt)
    const leaves = [...canonicalLeaves, authority.governanceCompletionLeaf(signed)]
    const head = await checkpoint(leaves, canonicalState, observed, history.keys.rotated)
    await expect(authority.replayGovernanceHistory(history.signedAnchor, history.pin, leaves,
      [...history.heads, observed, head])).rejects.toThrow(/receipt mismatch/)
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

describe('bounded-page governance replay session', () => {
  async function acceptedPrefix(size: number) {
    const session = await authority.createGovernanceReplaySession(history.signedAnchor, history.pin, history.heads[0]!)
    for (let index = 0; index < size; index++) {
      await session.appendLeaves([history.leaves[index]!], history.heads[index + 1]!)
      await session.sealCheckpoint(history.heads[index + 1]!)
    }
    return session
  }

  it('keeps pages tentative until the exact checkpoint is sealed, then lets the next action observe it', async () => {
    const session = await authority.createGovernanceReplaySession(history.signedAnchor, history.pin, history.heads[0]!)
    expect(session.snapshot().size).toBe(0)
    await session.appendLeaves([history.leaves[0]!], history.heads[1]!)
    expect(session.snapshot().size).toBe(0)
    expect(await session.sealCheckpoint(history.heads[1]!)).toBeUndefined()
    expect(session.snapshot().size).toBe(1)
    const sealedOne = session.snapshot()
    expect(session.snapshot()).toBe(sealedOne)
    await session.appendLeaves([history.leaves[1]!], history.heads[2]!)
    expect(session.snapshot().size).toBe(1)
    expect(session.snapshot().actorHeads).toEqual([])
    expect(session.snapshot()).toBe(sealedOne)
    await session.sealCheckpoint(history.heads[2]!)
    expect(session.snapshot().size).toBe(2)
    expect(session.snapshot()).not.toBe(sealedOne)
    expect(session.snapshot().actorHeads).toHaveLength(1)
    for (let index = 2; index < history.leaves.length; index++) {
      await session.appendLeaves([history.leaves[index]!], history.heads[index + 1]!)
      await session.sealCheckpoint(history.heads[index + 1]!)
    }
    expect(session.snapshot()).toEqual(await authority.replayGovernanceHistory(history.signedAnchor,
      history.pin, history.leaves, history.heads))
  })

  it('seals a checkpoint spanning multiple pages and accepts an action observing that new head', async () => {
    const firstBody = { review: 1 }
    const firstRevision = await revision(history.state, { kind: 'policy', body: firstBody,
      policyHash: await authority.observerPolicyHash(firstBody) }, history.keys.root)
    const firstState = await authority.applyAuthorityRevision(history.state, firstRevision)
    const secondBody = { review: 2 }
    const secondRevision = await revision(firstState, { kind: 'policy', body: secondBody,
      policyHash: await authority.observerPolicyHash(secondBody) }, history.keys.root)
    const secondState = await authority.applyAuthorityRevision(firstState, secondRevision)
    const leaves = [...history.leaves, authority.authorityRevisionLeaf(firstRevision), authority.authorityRevisionLeaf(secondRevision)]
    const spanning = await checkpoint(leaves, secondState, history.heads[7]!, history.keys.rotated)
    const session = await acceptedPrefix(7)
    await session.appendLeaves([leaves[7]!], spanning)
    await session.appendLeaves([leaves[8]!], spanning)
    expect(session.snapshot().size).toBe(7)
    await session.sealCheckpoint(spanning)
    expect(session.snapshot().size).toBe(9)
    const signed = await action(secondState, spanning, history.keys.alice, ALICE,
      '7'.repeat(64), history.second.integrated)
    leaves.push(authority.governanceCompletionLeaf(signed))
    const last = await checkpoint(leaves, secondState, spanning, history.keys.rotated)
    await session.appendLeaves([leaves[9]!], last)
    await session.sealCheckpoint(last)
    expect(session.snapshot().size).toBe(10)
    expect(session.snapshot()).toEqual(await authority.replayGovernanceHistory(history.signedAnchor,
      history.pin, leaves, [...history.heads, spanning, last]))
  })

  it('rejects pages crossing the declared checkpoint boundary and poisons the session', async () => {
    const session = await authority.createGovernanceReplaySession(history.signedAnchor, history.pin, history.heads[0]!)
    await expect(session.appendLeaves(history.leaves.slice(0, 2), history.heads[1]!)).rejects.toThrow(/boundary/)
    expect(() => session.snapshot()).toThrow(/failed session/)
    await expect(session.appendLeaves([history.leaves[0]!], history.heads[1]!)).rejects.toThrow(/failed session/)
  })

  it('requires exact tentative size and target identity before accepting a checkpoint', async () => {
    const short = await authority.createGovernanceReplaySession(history.signedAnchor, history.pin, history.heads[0]!)
    await expect(short.sealCheckpoint(history.heads[1]!)).rejects.toThrow(/size/)
    expect(() => short.snapshot()).toThrow(/failed session/)

    const changed = await authority.createGovernanceReplaySession(history.signedAnchor, history.pin, history.heads[0]!)
    await changed.appendLeaves([history.leaves[0]!], history.heads[1]!)
    await expect(changed.sealCheckpoint(history.heads[2]!)).rejects.toThrow(/target/)
    expect(() => changed.snapshot()).toThrow(/failed session/)
  })

  it('copies caller-owned leaf bytes before an asynchronous append can observe mutation', async () => {
    const session = await authority.createGovernanceReplaySession(history.signedAnchor, history.pin, history.heads[0]!)
    const owned = new Uint8Array(history.leaves[0]!)
    const pending = session.appendLeaves([owned], history.heads[1]!)
    owned[0] = owned[0]! ^ 1
    await pending
    await session.sealCheckpoint(history.heads[1]!)
    expect(session.snapshot().size).toBe(1)
  })

  it('rejects noncanonical, reordered and skipped history before coverage advances', async () => {
    const changed = await acceptedPrefix(0)
    const noncanonical = new Uint8Array([...history.leaves[0]!, 32])
    await expect(changed.appendLeaves([noncanonical], history.heads[1]!)).rejects.toThrow(/canonical/)
    expect(() => changed.snapshot()).toThrow(/failed session/)

    const reordered = await acceptedPrefix(0)
    await expect(reordered.appendLeaves([history.leaves[1]!], history.heads[1]!)).rejects.toThrow()
    expect(() => reordered.snapshot()).toThrow(/failed session/)

    const skipped = await acceptedPrefix(0)
    await expect(skipped.appendLeaves([history.leaves[0]!], history.heads[2]!)).rejects.toThrow(/forks/)
    expect(() => skipped.snapshot()).toThrow(/failed session/)
  })

  it('checks the signer authorized after a rotation leaf, including across a tentative page', async () => {
    const valid = await acceptedPrefix(5)
    await valid.appendLeaves([history.leaves[5]!], history.heads[6]!)
    expect(valid.snapshot().size).toBe(5)
    await valid.sealCheckpoint(history.heads[6]!)
    expect(valid.snapshot().size).toBe(6)

    const stale = await authority.signCheckpoint({ ...history.heads[6]!.statement,
      signerKeyId: await authority.signingKeyId(history.keys.provider.publicKey) }, history.keys.provider)
    const rejected = await acceptedPrefix(5)
    await rejected.appendLeaves([history.leaves[5]!], stale)
    await expect(rejected.sealCheckpoint(stale)).rejects.toThrow(/disagrees/)
    expect(() => rejected.snapshot()).toThrow(/failed session/)
  })

  it('rejects a duplicate operation and a future observed checkpoint in tentative actions', async () => {
    const prefix = await acceptedPrefix(7)
    const duplicate = await action(history.state, history.heads[7]!, history.keys.alice, ALICE,
      history.first.signed.statement.operationId, history.second.integrated)
    const duplicateLeaves = [...history.leaves, authority.governanceCompletionLeaf(duplicate)]
    const duplicateHead = await checkpoint(duplicateLeaves, history.state, history.heads[7]!, history.keys.rotated)
    await expect(prefix.appendLeaves([duplicateLeaves[7]!], duplicateHead)).rejects.toThrow(/Duplicate operation/)
    expect(() => prefix.snapshot()).toThrow(/failed session/)

    const future = await authority.signGovernanceAction({ ...history.second.signed.statement,
      operationId: '9'.repeat(64), observedCheckpointHash: WRONG,
      previousActionHash: history.second.integrated.actionHash,
      previousReceipt: history.second.integrated }, history.keys.alice)
    const futureLeaves = [...history.leaves, authority.governanceCompletionLeaf(future)]
    const futureHead = await checkpoint(futureLeaves, history.state, history.heads[7]!, history.keys.rotated)
    const rejected = await acceptedPrefix(7)
    await expect(rejected.appendLeaves([futureLeaves[7]!], futureHead)).rejects.toThrow(/unauthenticated checkpoint/)
    expect(() => rejected.snapshot()).toThrow(/failed session/)
  })

  it('rejects a changed prior receipt and bounded-page overflows', async () => {
    const prior = { ...history.second.integrated, leafHash: WRONG }
    const signed = await action(history.state, history.heads[7]!, history.keys.alice, ALICE,
      '8'.repeat(64), prior)
    const leaves = [...history.leaves, authority.governanceCompletionLeaf(signed)]
    const head = await checkpoint(leaves, history.state, history.heads[7]!, history.keys.rotated)
    const receiptSession = await acceptedPrefix(7)
    await expect(receiptSession.appendLeaves([leaves[7]!], head)).rejects.toThrow(/receipt mismatch/)

    const tooMany = await acceptedPrefix(0)
    await expect(tooMany.appendLeaves(Array.from({ length: 65 }, () => history.leaves[0]!),
      history.heads[1]!)).rejects.toThrow(/bounded dense page leaf/)
    const tooLarge = await acceptedPrefix(0)
    await expect(tooLarge.appendLeaves(Array.from({ length: 11 }, () => new Uint8Array(24 * 1024)),
      history.heads[1]!)).rejects.toThrow(/256 KiB/)
  })

  it('uses tentative actor state to reject two unlinked same-key actions in one checkpoint', async () => {
    const parsed = authority.parseCanonical(history.leaves[0]!) as unknown as {
      revision: authority.SignedAuthorityRevision
    }
    const initial = await authority.verifyAuthorityAnchor(history.signedAnchor, history.pin)
    const bound = await authority.applyAuthorityRevision(initial, parsed.revision)
    const first = await action(bound, history.heads[1]!, history.keys.alice, ALICE, 'a'.repeat(64))
    const second = await action(bound, history.heads[1]!, history.keys.alice, ALICE, 'b'.repeat(64))
    const leaves = [history.leaves[0]!, authority.governanceCompletionLeaf(first),
      authority.governanceCompletionLeaf(second)]
    const target = await checkpoint(leaves, bound, history.heads[1]!, history.keys.provider)
    const session = await acceptedPrefix(1)
    await expect(session.appendLeaves(leaves.slice(1), target)).rejects.toThrow(/predecessor mismatch/)
    expect(() => session.snapshot()).toThrow(/failed session/)
  })

  it('poisons concurrent use so neither overlapping call reports accepted progress', async () => {
    const session = await acceptedPrefix(0)
    const first = session.appendLeaves([history.leaves[0]!], history.heads[1]!)
    const second = session.sealCheckpoint(history.heads[1]!)
    await expect(second).rejects.toThrow(/failed session/)
    await expect(first).rejects.toThrow(/failed session/)
    expect(() => session.snapshot()).toThrow(/failed session/)
  })
})
