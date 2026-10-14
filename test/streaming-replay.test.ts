import { expect, it } from 'vitest'
import * as api from '../src/index.js'

const FEED = '1'.repeat(64)
const WORKSPACE = '2'.repeat(64)
const ALICE = '3'.repeat(64)

it('replays a mixed authenticated history beyond the complete-prefix input ceiling', async () => {
  const started = performance.now()
  const [root, recovery, provider, rotated, alice] = await Promise.all([
    api.generateSigningKey(), api.generateSigningKey(), api.generateSigningKey(),
    api.generateSigningKey(), api.generateSigningKey(),
  ])
  const anchor = await api.createAuthorityAnchor({ feedId: FEED, workspaceId: WORKSPACE,
    rootPublicKey: root.publicKey, recoveryPublicKey: recovery.publicKey,
    checkpointPublicKey: provider.publicKey })
  const signedAnchor = await api.signAuthorityAnchor(anchor, root, recovery)
  const pin = await api.anchorHash(anchor)
  let state = await api.verifyAuthorityAnchor(signedAnchor, pin)
  let frontier = api.emptyHistoryFrontier()
  const leaves: Uint8Array[] = []
  const heads: api.SignedCheckpoint[] = []

  async function append(leaf: Uint8Array) {
    leaves.push(leaf)
    frontier = await api.appendHistory(frontier, leaf)
  }
  async function seal(signer: CryptoKeyPair) {
    const current = api.authorityStateSnapshot(state)
    heads.push(await api.signCheckpoint({ version: 1, feedId: FEED, size: leaves.length,
      historyRoot: await api.historyFrontierRoot(frontier), authorityRoot: current.authorityRoot,
      policyEpoch: current.policyEpoch, signerKeyId: await api.signingKeyId(signer.publicKey),
      previous: heads.length ? await api.checkpointHash(heads.at(-1)!.statement) : null }, signer))
  }
  async function revise(operation: api.AuthorityOperation, authorityRoot?: api.Hash) {
    const current = api.authorityStateSnapshot(state)
    const signed = await api.signAuthorityRevision({ version: 1, feedId: FEED, workspaceId: WORKSPACE,
      number: current.revision + 1, previous: current.revisionHash, previousRoot: current.authorityRoot,
      expectedPolicyEpoch: current.policyEpoch, operation, authorityRoot: authorityRoot ?? current.authorityRoot,
      policyEpoch: current.policyEpoch + (operation.kind === 'policy' ? 1 : 0),
      signerKeyId: await api.signingKeyId(root.publicKey) }, root)
    state = await api.applyAuthorityRevision(state, signed)
    await append(api.authorityRevisionLeaf(signed))
  }

  await seal(provider)
  const actor: api.ActiveBinding = { subjectId: ALICE,
    keySpki: await api.exportSigningPublicKey(alice.publicKey), keyId: await api.signingKeyId(alice.publicKey),
    version: 1, scope: { kind: 'workspace', workspaceId: WORKSPACE }, actionClasses: ['document.read'],
    recipientKeyCommitment: null, status: 'active' }
  const actorRoot = await api.orderedMapRoot([{ key: await api.authorityMapKey(ALICE),
    valueHash: await api.authorityBindingHash(actor) }])
  await revise({ kind: 'bind', binding: actor }, actorRoot)
  await seal(provider)
  const current = api.authorityStateSnapshot(state)
  const signedAction = await api.signGovernanceAction({ version: 1, feedId: FEED, workspaceId: WORKSPACE,
    operationId: '4'.repeat(64), actorSubjectId: ALICE, actorKeyId: actor.keyId, actorVersion: 1,
    scope: { kind: 'workspace', workspaceId: WORKSPACE }, actionClass: 'document.read',
    authorityRevision: current.revision, authorityRevisionHash: current.revisionHash,
    authorityRoot: current.authorityRoot, policyEpoch: current.policyEpoch,
    observerPolicyHash: current.observerPolicyHash, intentCommitment: '5'.repeat(64),
    effectCommitment: '6'.repeat(64),
    observedCheckpointHash: await api.checkpointHash(heads.at(-1)!.statement),
    previousActionHash: null, previousReceipt: null }, alice)
  await append(api.governanceCompletionLeaf(signedAction))
  await seal(provider)
  await revise({ kind: 'rotate-checkpoint', checkpointKeySpki: await api.exportSigningPublicKey(rotated.publicKey),
    checkpointKeyId: await api.signingKeyId(rotated.publicKey) })
  await seal(rotated)

  for (let index = 0; index < 10_001; index++) {
    await revise({ kind: 'policy', body: null, policyHash: null })
    if ([100, 1000, 10_000, 10_004].includes(leaves.length)) await seal(rotated)
  }
  expect(leaves.length).toBe(10_004)
  expect(heads.at(-1)!.statement.historyRoot).toBe(await api.merkleRoot(leaves))
  await expect(api.replayGovernanceHistory(signedAnchor, pin, leaves, heads)).rejects.toThrow(/bounded dense leaf/)

  const generatedMs = performance.now() - started
  const session = await api.createGovernanceReplaySession(signedAnchor, pin, heads[0]!)
  let offset = 0
  const samples: { size: number; elapsedMs: number; heapMiB: number }[] = []
  const replayStarted = performance.now()
  for (const head of heads.slice(1)) {
    while (offset < head.statement.size) {
      const next = Math.min(offset + 64, head.statement.size)
      await session.appendLeaves(leaves.slice(offset, next), head)
      offset = next
    }
    await session.sealCheckpoint(head)
    if ([100, 1000, 10_000, 10_004].includes(head.statement.size)) {
      samples.push({ size: head.statement.size, elapsedMs: performance.now() - replayStarted,
        heapMiB: process.memoryUsage().heapUsed / 1024 / 1024 })
    }
  }
  expect(session.snapshot()).toMatchObject({ size: 10_004,
    checkpointHash: await api.checkpointHash(heads.at(-1)!.statement),
    authorityRoot: api.authorityStateSnapshot(state).authorityRoot,
    policyEpoch: 10_001,
    actorHeads: [{ actorKeyId: actor.keyId, actionHash: await api.governanceActionHash(signedAction.statement) }] })
  console.info('streaming replay benchmark', JSON.stringify({ generatedMs, samples }))
}, 120_000)

it('replays 256 receipt-linked actions across eight actors and 32 checkpoints', async () => {
  const started = performance.now()
  const [root, recovery, provider] = await Promise.all([
    api.generateSigningKey(), api.generateSigningKey(), api.generateSigningKey(),
  ])
  const actorPairs = await Promise.all(Array.from({ length: 8 }, () => api.generateSigningKey()))
  const actorIds = actorPairs.map((_, index) => (index + 4).toString(16).repeat(64))
  const anchor = await api.createAuthorityAnchor({ feedId: FEED, workspaceId: WORKSPACE,
    rootPublicKey: root.publicKey, recoveryPublicKey: recovery.publicKey,
    checkpointPublicKey: provider.publicKey })
  const signedAnchor = await api.signAuthorityAnchor(anchor, root, recovery)
  const pin = await api.anchorHash(anchor)
  let state = await api.verifyAuthorityAnchor(signedAnchor, pin)
  let frontier = api.emptyHistoryFrontier()
  const leaves: Uint8Array[] = []
  const heads: api.SignedCheckpoint[] = []
  async function append(leaf: Uint8Array) {
    leaves.push(leaf)
    frontier = await api.appendHistory(frontier, leaf)
  }
  async function seal() {
    const current = api.authorityStateSnapshot(state)
    heads.push(await api.signCheckpoint({ version: 1, feedId: FEED, size: leaves.length,
      historyRoot: await api.historyFrontierRoot(frontier), authorityRoot: current.authorityRoot,
      policyEpoch: current.policyEpoch, signerKeyId: await api.signingKeyId(provider.publicKey),
      previous: heads.length ? await api.checkpointHash(heads.at(-1)!.statement) : null }, provider))
  }
  await seal()
  for (let index = 0; index < actorPairs.length; index++) {
    const pair = actorPairs[index]!
    const binding: api.ActiveBinding = { subjectId: actorIds[index]!,
      keySpki: await api.exportSigningPublicKey(pair.publicKey),
      keyId: await api.signingKeyId(pair.publicKey), version: 1,
      scope: { kind: 'workspace', workspaceId: WORKSPACE }, actionClasses: ['document.read'],
      recipientKeyCommitment: null, status: 'active' }
    const current = api.authorityStateSnapshot(state)
    const entries = await Promise.all([...current.bindings, binding].map(async item => ({
      key: await api.authorityMapKey(item.subjectId), valueHash: await api.authorityBindingHash(item),
    })))
    entries.sort((a, b) => a.key.localeCompare(b.key))
    const signed = await api.signAuthorityRevision({ version: 1, feedId: FEED, workspaceId: WORKSPACE,
      number: current.revision + 1, previous: current.revisionHash, previousRoot: current.authorityRoot,
      expectedPolicyEpoch: 0, operation: { kind: 'bind', binding },
      authorityRoot: await api.orderedMapRoot(entries), policyEpoch: 0,
      signerKeyId: await api.signingKeyId(root.publicKey) }, root)
    state = await api.applyAuthorityRevision(state, signed)
    await append(api.authorityRevisionLeaf(signed))
  }
  await seal()

  type LastAction = { signed: api.SignedAction; leaf: Uint8Array; index: number; head: api.SignedCheckpoint }
  let last: (LastAction | null)[] = actorPairs.map(() => null)
  for (let batch = 0; batch < 32; batch++) {
    const next: Omit<LastAction, 'head'>[] = []
    const observed = heads.at(-1)!
    for (let actor = 0; actor < actorPairs.length; actor++) {
      const prior = last[actor]
      const receipt: api.CompletionReceipt | null = prior ? {
        version: 1, status: 'integrated', feedId: FEED,
        operationId: prior.signed.statement.operationId,
        actionHash: await api.governanceActionHash(prior.signed.statement),
        effectCommitment: prior.signed.statement.effectCommitment,
        leafIndex: prior.index, leafHash: await api.hashLeaf(prior.leaf),
        checkpoint: prior.head,
        inclusionProof: await api.inclusionProof(leaves.slice(0, prior.head.statement.size), prior.index),
      } : null
      const current = api.authorityStateSnapshot(state)
      const signed = await api.signGovernanceAction({ version: 1, feedId: FEED, workspaceId: WORKSPACE,
        operationId: (batch * actorPairs.length + actor + 1).toString(16).padStart(64, '0'),
        actorSubjectId: actorIds[actor]!, actorKeyId: await api.signingKeyId(actorPairs[actor]!.publicKey),
        actorVersion: 1, scope: { kind: 'workspace', workspaceId: WORKSPACE },
        actionClass: 'document.read', authorityRevision: current.revision,
        authorityRevisionHash: current.revisionHash, authorityRoot: current.authorityRoot,
        policyEpoch: current.policyEpoch, observerPolicyHash: current.observerPolicyHash,
        intentCommitment: 'e'.repeat(64), effectCommitment: 'f'.repeat(64),
        observedCheckpointHash: await api.checkpointHash(observed.statement),
        previousActionHash: receipt?.actionHash ?? null, previousReceipt: receipt }, actorPairs[actor]!)
      const leaf = api.governanceCompletionLeaf(signed)
      next.push({ signed, leaf, index: leaves.length })
      await append(leaf)
    }
    await seal()
    last = next.map(item => ({ ...item, head: heads.at(-1)! }))
  }
  expect(leaves).toHaveLength(264)
  expect(heads).toHaveLength(34)
  const generationMs = performance.now() - started

  const session = await api.createGovernanceReplaySession(signedAnchor, pin, heads[0]!)
  let offset = 0
  const replayStarted = performance.now()
  for (const head of heads.slice(1)) {
    await session.appendLeaves(leaves.slice(offset, head.statement.size), head)
    if (head.statement.size === 16) {
      expect(session.snapshot().size).toBe(8)
      expect(session.snapshot().actorHeads).toEqual([])
    }
    await session.sealCheckpoint(head)
    offset = head.statement.size
  }
  const replayMs = performance.now() - replayStarted
  const final = session.snapshot()
  expect(final.size).toBe(264)
  expect(final.actorHeads).toHaveLength(8)
  expect(final).toEqual(await api.replayGovernanceHistory(signedAnchor, pin, leaves, heads))
  console.info('action-heavy replay benchmark', JSON.stringify({ generationMs, replayMs,
    heapMiB: process.memoryUsage().heapUsed / 1024 / 1024, actors: 8, actions: 256, checkpoints: 34 }))
}, 120_000)
